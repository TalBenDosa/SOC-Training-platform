"use client";
/**
 * "Report a problem" — a global, always-available button for TECHNICAL issues
 * (a page that errored, a button that did nothing, something that would not
 * load). Distinct from ReportIssue.tsx, which reports a CONTENT defect next to
 * a specific room/quiz. This one floats on every app page so a learner can flag
 * a bug the moment they hit it, from wherever they are.
 *
 * It reuses the existing /api/feedback endpoint (target_kind "other") — no new
 * table or route — and auto-captures the page URL, browser, and viewport so the
 * report is actionable without a reply. Reports land in the same admin triage
 * inbox at /admin/feedback, tagged context.category = "technical".
 */
import { useId, useRef, useState } from "react";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { displayError } from "@/lib/http/apiError";
import { Bug, X, Check, Loader2 } from "lucide-react";

export function ReportProblem() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Dialog keyboard contract: focus moves in, Tab is trapped, Escape closes,
  // and focus returns to the floating trigger on close.
  useFocusTrap(open, dialogRef, { onEscape: () => setOpen(false), initialFocus: textareaRef });

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!message.trim()) return;
    setBusy(true); setError(null);
    try {
      // Auto-captured so a bug report is actionable on its own — the reporter
      // shouldn't have to describe which page they were on or what browser.
      const context =
        typeof window !== "undefined"
          ? {
              category: "technical",
              page: window.location.pathname + window.location.search,
              url: window.location.href,
              userAgent: navigator.userAgent,
              viewport: `${window.innerWidth}x${window.innerHeight}`,
            }
          : { category: "technical" };

      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_kind: "other", target_id: "technical", context, message }),
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d?.error ?? "Could not send. Please try again.");
      }
      // Keep focus inside the dialog — the submit button is about to unmount.
      dialogRef.current?.focus();
      setSent(true);
      setTimeout(() => { setOpen(false); setSent(false); setMessage(""); }, 1600);
    } catch (err) {
      setError(displayError(err, "Could not send."));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      {/* Floating trigger — bottom-right, subtle until hovered. */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="fixed bottom-4 right-4 z-40 inline-flex items-center gap-2 rounded-full border border-border bg-bg-elevated/95 px-3.5 py-2 text-xs font-semibold text-slate-300 shadow-lg backdrop-blur transition hover:border-neon-amber/50 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-amber/40"
        title="Report a technical problem"
        aria-label="Report a problem (technical issue)"
      >
        <Bug className="h-4 w-4 text-neon-amber" />
        <span className="hidden sm:inline">Report a problem</span>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-[60] flex items-center justify-center bg-black/70 p-4"
          onClick={e => { if (e.target === e.currentTarget) setOpen(false); }}
        >
          <div
            ref={dialogRef}
            role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}
            className="w-full max-w-md rounded-xl border border-border bg-bg-elevated p-5 shadow-2xl outline-none"
          >
            <div className="mb-3 flex items-center justify-between">
              <h2 id={titleId} className="flex items-center gap-2 text-sm font-bold text-white">
                <Bug className="h-4 w-4 text-neon-amber" aria-hidden="true" /> Report a problem
              </h2>
              <button type="button" onClick={() => setOpen(false)} aria-label="Close" className="rounded p-1 text-slate-400 hover:text-white">
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Persistent live region so the "Thanks" confirmation is announced. */}
            <div role="status">
              {sent && (
                <p className="flex items-center gap-2 py-6 text-sm text-neon-green">
                  <Check className="h-4 w-4" aria-hidden="true" /> Thanks — we&apos;ve logged it and will take a look.
                </p>
              )}
            </div>
            {!sent && (
              <form onSubmit={submit}>
                <label className="mb-1.5 block text-xs text-slate-400" htmlFor="rp-msg">
                  Something not working? A page error, a button that does nothing, something that
                  wouldn&apos;t load — tell us what happened.
                </label>
                <textarea
                  id="rp-msg" rows={4} value={message} onChange={e => setMessage(e.target.value)} ref={textareaRef}
                  maxLength={2000} /* P5-16: the server keeps 2000 characters — say so here instead of cutting silently */
                  className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-neon-amber/50 focus:outline-none focus:ring-2 focus:ring-neon-amber/25"
                  placeholder="The Dashboard didn't load — I clicked Start and the page went blank."
                />
                {error && <p role="alert" className="mt-2 text-[11px] text-severity-high">{error}</p>}
                <p className="mt-2 text-[10px] text-slate-500">
                  We automatically include the page you&apos;re on and your browser, so you don&apos;t have to.
                </p>
                <div className="mt-3 flex items-center justify-end gap-2">
                  <button type="button" onClick={() => setOpen(false)}
                    className="rounded-lg border border-border px-3 py-1.5 text-xs text-slate-300 hover:text-white">Cancel</button>
                  <button type="submit" disabled={busy || !message.trim()}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-3 py-1.5 text-xs font-bold text-neon-amber transition hover:bg-neon-amber/20 disabled:opacity-40">
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
