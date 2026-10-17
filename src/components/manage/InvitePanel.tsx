"use client";
/**
 * Invite people by email (org-admin /manage). The only way to add an INSTRUCTOR:
 * staff roles are granted only through an emailed invitation accepted from that
 * mailbox (an existing account proves nothing about who owns an address). Students
 * normally join with the class code; an emailed invite works for them too.
 * Data: POST /api/org/invites (named-only, daily-capped server-side). QA-ADMIN-1.
 */
import { useId, useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Mail } from "lucide-react";

const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function InvitePanel() {
  const ids = useId();
  const [emails, setEmails] = useState("");
  const [role, setRole] = useState<"instructor" | "student">("instructor");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  const list = [...new Set(emails.split(/[\s,;]+/).map(e => e.trim().toLowerCase()).filter(Boolean))];
  const invalid = list.filter(e => !EMAIL.test(e));

  async function send() {
    setBusy(true); setMsg(null);
    try {
      const res = await fetch("/api/org/invites", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ role, emails: list }),
      });
      const d = await res.json().catch(() => ({})) as { error?: string; invites?: unknown[]; emailed?: number; email_failed?: number; email_configured?: boolean };
      if (!res.ok) { setMsg({ ok: false, text: d.error ?? "Couldn't send the invitations. Try again." }); return; }
      const n = d.invites?.length ?? 0;
      const failed = d.email_failed ?? 0;
      setMsg({
        ok: failed === 0 && d.email_configured !== false,
        text: d.email_configured === false
          ? `${n} invitation${n === 1 ? "" : "s"} created, but email is not configured on this deployment, so nothing was sent.`
          : failed > 0
            ? `${n - failed} of ${n} invitation emails sent; ${failed} could not be delivered. Check the addresses and try those again.`
            : `${n} invitation${n === 1 ? "" : "s"} sent. Each link works once, only for that address, and expires if unused.`,
      });
      if (failed === 0) setEmails("");
    } catch {
      setMsg({ ok: false, text: "Network problem: the invitations were not sent. Try again." });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      <h2 className="flex items-center gap-2 text-sm font-bold text-white">
        <Mail className="h-4 w-4 text-cyber-300" aria-hidden="true" /> Invite by email
      </h2>
      <p className="mt-1 text-xs text-slate-400">
        Instructors can only be added this way. Students usually join with the class code, but you can invite them here too.
      </p>
      <div className="mt-3 grid gap-3 sm:grid-cols-[1fr_auto]">
        <div>
          <label htmlFor={`${ids}-emails`} className="mb-1 block text-[11px] font-semibold text-slate-400">Email addresses (one per line, or separated by commas)</label>
          <textarea
            id={`${ids}-emails`} rows={2} value={emails} onChange={e => setEmails(e.target.value)}
            aria-invalid={invalid.length > 0 || undefined}
            className="w-full rounded-md border border-border bg-bg px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none focus:ring-2 focus:ring-cyber-500/30"
            placeholder="dana.levi@college.ac.il"
          />
          {invalid.length > 0 && <p className="mt-1 text-[11px] text-severity-high">Not an email address: {invalid.slice(0, 3).join(", ")}</p>}
        </div>
        <div className="flex flex-col gap-2 sm:w-44">
          <label htmlFor={`${ids}-role`} className="block text-[11px] font-semibold text-slate-400">Role</label>
          <select
            id={`${ids}-role`} value={role} onChange={e => setRole(e.target.value as "instructor" | "student")}
            className="h-9 rounded-md border border-border bg-bg px-2 text-sm text-white focus:border-cyber-500/50 focus:outline-none"
          >
            <option value="instructor">Instructor</option>
            <option value="student">Student</option>
          </select>
          <Button variant="primary" size="sm" onClick={send} disabled={busy || list.length === 0 || invalid.length > 0}>
            {busy ? "Sending…" : `Send ${list.length > 1 ? `${list.length} invitations` : "invitation"}`}
          </Button>
        </div>
      </div>
      {msg && <p role="status" className={`mt-2 text-xs ${msg.ok ? "text-neon-green" : "text-neon-amber"}`}>{msg.text}</p>}
    </Card>
  );
}
