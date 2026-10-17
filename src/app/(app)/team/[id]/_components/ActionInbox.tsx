"use client";
import { useState } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { BellRing } from "lucide-react";
import type { Ev, Me, RosterMember } from "@/lib/team/types";
import { actionInbox, UPDATE_DECISIONS, MIN_RESPONSE_CHARS, type InboxItem } from "@/lib/team/actionInbox";

// ── Action required: the injects waiting for THIS player's answer, at the top of the console ──
// 2026-10-18 review: no ticket, decoy or management request was handled in four exercises.
const TITLE: Record<InboxItem["kind"], string> = { ticket: "Help-desk ticket", update: "Update", mgmt: "Management request", elevation: "Elevation from Tier-2" };
const ASK: Record<InboxItem["kind"], string> = {
  elevation: "",
  ticket: "What did you do, how did you verify the caller, and was anything shared?",
  update: "What did you check, and what does it mean for us?",
  mgmt: "Your status update: what we know, what is contained, what happens next.",
};

export function ActionInbox({ events, me, roster, act }: { events: Ev[]; me: Me; roster: RosterMember[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const items = actionInbox(events, { id: me.id, role: me.role }, roster);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [busy, setBusy] = useState<number | null>(null);
  if (items.length === 0) return null;

  async function send(it: InboxItem, type: string, payload: Record<string, unknown>) {
    setBusy(it.seq);
    const ok = await act(type, payload);
    setBusy(null);
    if (ok) setNotes(n => { const c = { ...n }; delete c[it.seq]; return c; });
  }

  return (
    <div data-tour="action-inbox" role="region" aria-label="Action required">
    <Card className="border-neon-amber/50 bg-neon-amber/[0.04]">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white">
        <BellRing className="h-4 w-4 text-neon-amber" aria-hidden="true" /> Action required <span className="rounded-full bg-neon-amber/20 px-1.5 text-[11px] text-neon-amber">{items.length}</span>
      </h3>
      <ul className="mt-2 space-y-2">
        {items.map(it => {
          if (it.kind === "elevation") return (
            <li key={`elev-${it.seq}`} className="rounded-lg border border-border bg-bg px-2.5 py-2 text-xs">
              <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-neon-amber">{TITLE.elevation}</span><bdi>{it.text}</bdi></p>
              <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                {!it.taken
                  ? <Button size="sm" variant="primary" disabled={busy === it.seq} onClick={() => send(it, "elevation.acknowledged", { event_id: it.eventId })}>Take the hunt</Button>
                  : <span className="text-[10px] text-slate-400">Taken. Record a hunt finding linked to it in Threat hunt below.</span>}
                <Button size="sm" variant="outline" onClick={() => document.querySelector("[data-tour=hunt-console]")?.scrollIntoView({ behavior: "smooth", block: "start" })}>Go to Threat hunt</Button>
              </div>
            </li>
          );
          const note = (notes[it.seq] ?? "").trim();
          const short = note.length < MIN_RESPONSE_CHARS;
          const id = `inbox-note-${it.seq}`;
          return (
            <li key={it.seq} className="rounded-lg border border-border bg-bg px-2.5 py-2 text-xs">
              <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-neon-amber">{TITLE[it.kind]}</span><bdi>{it.text}</bdi></p>
              <label htmlFor={id} className="mt-1.5 block text-[10px] text-slate-400">{ASK[it.kind]}</label>
              <textarea id={id} rows={2} value={notes[it.seq] ?? ""} onChange={e => setNotes(n => ({ ...n, [it.seq]: e.target.value }))}
                className="mt-0.5 w-full rounded border border-border bg-bg-elevated px-2 py-1 text-[11px] text-slate-200 focus:border-cyber-500/50 focus:outline-none" />
              {short && <p className="text-[10px] text-slate-500">At least {MIN_RESPONSE_CHARS} characters, then choose.</p>}
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                {it.kind === "ticket" && <>
                  <Button size="sm" variant="primary" disabled={short || busy === it.seq} onClick={() => send(it, "ticket.answered", { ticket_seq: it.seq, decision: "rejected", response: note, details: note })}>Refuse &amp; report to security</Button>
                  <Button size="sm" variant="outline" disabled={short || busy === it.seq} onClick={() => send(it, "ticket.answered", { ticket_seq: it.seq, decision: "handled", response: note, details: note })}>Handle as asked</Button>
                </>}
                {it.kind === "update" && UPDATE_DECISIONS.map(d => (
                  <Button key={d.id} size="sm" variant="outline" title={d.hint} disabled={short || busy === it.seq}
                    onClick={() => send(it, "inject.responded", { inject_seq: it.seq, inject_id: it.injectId || undefined, decision: d.id, note })}>{d.label}</Button>
                ))}
                {it.kind === "mgmt" && (
                  <Button size="sm" variant="primary" disabled={short || busy === it.seq}
                    onClick={() => send(it, "inject.responded", { inject_seq: it.seq, inject_id: it.injectId || undefined, decision: "status", note })}>Send status</Button>
                )}
              </div>
              {it.kind === "mgmt" && <p className="mt-1 text-[10px] text-slate-500">No SOC Manager on this team, so this one is yours.</p>}
            </li>
          );
        })}
      </ul>
    </Card>
    </div>
  );
}
