"use client";
import { useState, useMemo } from "react";
import { Button } from "@/components/ui/Button";
import type { Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── G-13: war-room — a durable team chat (message.sent is already gate-allowed) ──
export function WarRoom({ events, me, nameOf, act }: { events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const msgs = useMemo(() => events.filter(e => e.type === "message.sent"), [events]);
  const canPost = !!(me.role && me.role !== "observer") && msg.trim().length > 0;
  async function send() {
    if (!canPost) return;
    setBusy(true); const ok = await act("message.sent", { text: msg.trim() }); setBusy(false);
    if (ok) setMsg("");
  }
  return (
    <div>
      {msgs.length === 0 ? <p className="text-xs text-slate-500">No messages yet — coordinate the response here. Everyone on the team sees this channel.</p> : (
        <div className="mb-2 max-h-56 space-y-1.5 overflow-y-auto">
          {msgs.slice().reverse().map(e => (
            <p key={e.seq} className="break-words text-[11px] text-slate-300"><span className="font-medium text-slate-200">{nameOf(e.actor_id)}:</span> {asStr((e.payload as { text?: string }).text).slice(0, 1000)}</p>
          ))}
        </div>
      )}
      <div className="flex gap-2">
        <input value={msg} onChange={e => setMsg(e.target.value)} onKeyDown={e => { if (e.key === "Enter") send(); }} placeholder="Message the team…" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <Button variant="outline" size="sm" disabled={busy || !canPost} onClick={send}>Send</Button>
      </div>
    </div>
  );
}
