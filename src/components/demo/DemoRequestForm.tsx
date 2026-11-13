"use client";
import { useState } from "react";
import { CalendarClock, CheckCircle2 } from "lucide-react";
import { Button } from "@/components/ui/Button";
import { ORG_TYPES, TEAM_SIZES } from "@/lib/demo/demoRequest";

const FIELD = "h-10 w-full rounded-md border border-border bg-bg px-3 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30";
const LABEL = "mb-1.5 block text-xs font-semibold text-slate-300";

/** The /demo page's request form: posts to /api/demo-request, which emails the platform owner. */
export function DemoRequestForm({ bookingUrl }: { bookingUrl: string | null }) {
  const [form, setForm] = useState({ name: "", email: "", organization: "", role: "", orgType: "", teamSize: "", availability: "", message: "", website: "" });
  const [consent, setConsent] = useState(false);
  const [status, setStatus] = useState<"idle" | "sending" | "sent">("idle");
  const [error, setError] = useState<{ text: string; field?: string } | null>(null);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => setForm(f => ({ ...f, [k]: e.target.value }));

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setStatus("sending");
    try {
      const res = await fetch("/api/demo-request", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...form, consent }),
      });
      const data = await res.json().catch(() => ({})) as { ok?: boolean; error?: string; field?: string };
      if (res.ok && data.ok) { setStatus("sent"); return; }
      setError({ text: data.error ?? "Something went wrong. Please try again.", field: data.field });
    } catch {
      setError({ text: "Couldn't reach the server. Check your connection and try again." });
    }
    setStatus("idle");
  }

  if (status === "sent") {
    return (
      <div role="status" className="space-y-4 py-6 text-center">
        <CheckCircle2 className="mx-auto h-10 w-10 text-neon-green" aria-hidden="true" />
        <h3 className="text-lg font-bold text-white">Request received</h3>
        <p className="mx-auto max-w-sm text-sm leading-relaxed text-slate-300">
          Thanks, {form.name.split(" ")[0] || "there"}. We&apos;ll reply to {form.email} within one business day to set a time.
        </p>
        {bookingUrl && (
          <a href={bookingUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-2 text-sm font-semibold text-cyber-300 underline underline-offset-2 hover:text-cyber-200">
            <CalendarClock className="h-4 w-4" aria-hidden="true" /> Or pick a time yourself now
          </a>
        )}
      </div>
    );
  }

  const invalid = (f: string) => error?.field === f ? { "aria-invalid": true as const, "aria-describedby": "demo-error" } : {};
  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor="demo-name" className={LABEL}>Full name</label>
          <input id="demo-name" required autoComplete="name" value={form.name} onChange={set("name")} maxLength={100} className={FIELD} {...invalid("name")} />
        </div>
        <div>
          <label htmlFor="demo-email" className={LABEL}>Work email</label>
          <input id="demo-email" type="email" required autoComplete="email" value={form.email} onChange={set("email")} maxLength={254} placeholder="you@organization.com" className={FIELD} {...invalid("email")} />
        </div>
        <div>
          <label htmlFor="demo-org" className={LABEL}>Organization</label>
          <input id="demo-org" required autoComplete="organization" value={form.organization} onChange={set("organization")} maxLength={120} className={FIELD} {...invalid("organization")} />
        </div>
        <div>
          <label htmlFor="demo-role" className={LABEL}>Your role <span className="font-normal text-slate-500">(optional)</span></label>
          <input id="demo-role" autoComplete="organization-title" value={form.role} onChange={set("role")} maxLength={80} placeholder="Program lead, SOC manager ..." className={FIELD} />
        </div>
        <div>
          <label htmlFor="demo-type" className={LABEL}>Organization type</label>
          <select id="demo-type" required value={form.orgType} onChange={set("orgType")} className={FIELD} {...invalid("orgType")}>
            <option value="" disabled>Choose one</option>
            {ORG_TYPES.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
          </select>
        </div>
        <div>
          <label htmlFor="demo-size" className={LABEL}>Learners</label>
          <select id="demo-size" required value={form.teamSize} onChange={set("teamSize")} className={FIELD} {...invalid("teamSize")}>
            <option value="" disabled>Roughly how many</option>
            {TEAM_SIZES.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label htmlFor="demo-when" className={LABEL}>Good times for a 30-minute call <span className="font-normal text-slate-500">(optional)</span></label>
        <input id="demo-when" value={form.availability} onChange={set("availability")} maxLength={200} placeholder="e.g. Sunday to Thursday mornings, Israel time" className={FIELD} />
      </div>
      <div>
        <label htmlFor="demo-msg" className={LABEL}>What should we focus on? <span className="font-normal text-slate-500">(optional)</span></label>
        <textarea id="demo-msg" value={form.message} onChange={set("message")} maxLength={2000} rows={4}
          className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
          placeholder="Your course or team, the tools you train on, team exercises, instructor reporting ..." />
      </div>
      {/* Honeypot: hidden from people and screen readers; a bot that fills it is not sent on. */}
      <div aria-hidden="true" className="absolute left-[-9999px] top-auto h-px w-px overflow-hidden">
        <label htmlFor="demo-website">Website</label>
        <input id="demo-website" tabIndex={-1} autoComplete="off" value={form.website} onChange={set("website")} />
      </div>
      <label className="flex items-start gap-2.5 text-xs leading-relaxed text-slate-300">
        <input id="demo-consent" type="checkbox" checked={consent} onChange={e => setConsent(e.target.checked)} className="mt-0.5 h-4 w-4 accent-cyan-400" {...invalid("consent")} />
        <span>
          You may contact me about this demo. We use these details only to arrange and follow up on it; see{" "}
          <a href="/privacy" className="text-cyber-300 underline underline-offset-2 hover:text-cyber-200">Privacy &amp; data</a>.
        </span>
      </label>
      {error && (
        <div id="demo-error" role="alert" className="rounded border border-severity-high/40 bg-severity-high/10 px-3 py-2 text-xs text-severity-high">
          {error.text}
        </div>
      )}
      <Button type="submit" variant="primary" size="lg" className="w-full" disabled={status === "sending"}>
        {status === "sending" ? "Sending..." : "Request a demo"}
      </Button>
      {bookingUrl && (
        <p className="text-center text-xs text-slate-400">
          Prefer to choose a slot yourself?{" "}
          <a href={bookingUrl} target="_blank" rel="noopener noreferrer" className="text-cyber-300 underline underline-offset-2 hover:text-cyber-200">Open the calendar</a>
        </p>
      )}
    </form>
  );
}
