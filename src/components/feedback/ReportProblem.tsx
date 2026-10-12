"use client";
/**
 * "Report a problem" — a global, always-available button. It floats on every app page so a
 * learner can flag something the moment they hit it, from wherever they are.
 *
 * When the screen has published where the learner is (lesson page, room task, quiz question,
 * scenario, live-feed log — see lib/feedback/reportLocation), the dialog shows that location
 * and files the report against it as a CONTENT report, so the triage inbox can say exactly
 * which page / question / log it is about. The learner can switch it to a technical problem
 * (a page that errored, a button that did nothing). With no published location it is a
 * technical report, as before. Either way the page URL, browser and viewport ride along.
 *
 * Reuses /api/feedback; reports land in the admin triage inbox (/admin/feedback).
 */
import { useId, useRef, useState } from "react";
import { useFocusTrap } from "@/lib/a11y/useFocusTrap";
import { displayError } from "@/lib/http/apiError";
import { useReportLocation } from "@/lib/feedback/reportLocation";
import { Bug, X, Check, Loader2, MapPin } from "lucide-react";
import { cn } from "@/lib/utils";

type About = "content" | "technical";

export function ReportProblem() {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState("");
  const [about, setAbout] = useState<About>("content");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const location = useReportLocation();
  const isContent = !!location && about === "content";

  // Dialog keyboard contract: focus moves in, Tab is trapped, Escape closes,
  // and focus returns to the floating trigger on close.
  useFocusTrap(open, dialogRef, { onEscape: () => setOpen(false), initialFocus: textareaRef });

  function openDialog() {
    setAbout("content");
    setOpen(true);
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!message.trim()) return;
    setBusy(true); setError(null);
    try {
      // Auto-captured so a report is actionable on its own — the reporter shouldn't
      // have to describe which page they were on, what was on screen, or what browser.
      const page = typeof window !== "undefined"
        ? { page: window.location.pathname + window.location.search, url: window.location.href, userAgent: navigator.userAgent, viewport: `${window.innerWidth}x${window.innerHeight}` }
        : {};
      const where = location ? { where: location.where, ...(location.step ? { step: location.step } : {}), ...(location.shown ? { shown: location.shown } : {}) } : {};
      const body = isContent
        ? { target_kind: location!.kind, target_id: location!.targetId, context: { category: "content", ...where, ...page }, message }
        : { target_kind: "other", target_id: "technical", context: { category: "technical", ...where, ...page }, message };

      const res = await fetch("/api/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
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
        onClick={openDialog}
        className="fixed bottom-4 right-4 z-40 inline-flex items-center gap-2 rounded-full border border-border bg-bg-elevated/95 px-3.5 py-2 text-xs font-semibold text-slate-300 shadow-lg backdrop-blur transition hover:border-neon-amber/50 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-neon-amber/40"
        title="Report a problem"
        aria-label="Report a problem"
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
                {location && (
                  <>
                    <div className="mb-3 rounded-lg border border-border bg-bg px-3 py-2">
                      <p className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                        <MapPin className="h-3 w-3" aria-hidden="true" /> You are reporting from
                      </p>
                      <p className="mt-1 text-xs font-semibold text-white" dir="auto">{location.where}</p>
                      {location.step && <p className="text-[11px] text-cyber-300">{location.step}</p>}
                      {location.shown && <p className="mt-1 line-clamp-2 text-[11px] text-slate-400" dir="auto">{location.shown}</p>}
                    </div>
                    <fieldset className="mb-3">
                      <legend className="mb-1.5 text-xs text-slate-400">What kind of problem?</legend>
                      <div className="grid grid-cols-2 gap-2">
                        {([
                          ["content", "Something in this content", "A wrong answer, a confusing question, a broken log"],
                          ["technical", "A technical problem", "A page error, a button that did nothing"],
                        ] as const).map(([value, label, hint]) => (
                          <label key={value} className={cn(
                            "cursor-pointer rounded-lg border px-2.5 py-2 text-left transition",
                            about === value ? "border-neon-amber/50 bg-neon-amber/10" : "border-border hover:border-border-strong",
                          )}>
                            <input type="radio" name="rp-about" value={value} checked={about === value} onChange={() => setAbout(value)} className="sr-only" />
                            <span className="block text-xs font-semibold text-white">{label}</span>
                            <span className="block text-[10px] leading-snug text-slate-500">{hint}</span>
                          </label>
                        ))}
                      </div>
                    </fieldset>
                  </>
                )}
                <label className="mb-1.5 block text-xs text-slate-400" htmlFor="rp-msg">
                  {isContent
                    ? "What's wrong with it? Tell us what you expected and what you saw."
                    : "Something not working? A page error, a button that does nothing, something that wouldn't load: tell us what happened."}
                </label>
                <textarea
                  id="rp-msg" rows={4} value={message} onChange={e => setMessage(e.target.value)} ref={textareaRef} dir="auto"
                  maxLength={2000} /* P5-16: the server keeps 2000 characters — say so here instead of cutting silently */
                  className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-neon-amber/50 focus:outline-none focus:ring-2 focus:ring-neon-amber/25"
                  placeholder={isContent ? "The marked answer looks wrong: 4625 is a failed logon, not a successful one." : "The Dashboard didn't load: I clicked Start and the page went blank."}
                />
                {error && <p role="alert" className="mt-2 text-[11px] text-severity-high">{error}</p>}
                <p className="mt-2 text-[10px] text-slate-500">
                  {location
                    ? "We include where you are and what was on screen, plus your browser, so you don't have to."
                    : "We automatically include the page you're on and your browser, so you don't have to."}
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
