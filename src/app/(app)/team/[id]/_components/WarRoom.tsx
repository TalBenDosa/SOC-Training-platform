"use client";
import { useState, useMemo, useEffect, useRef } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { MessagesSquare, Send } from "lucide-react";
import type { Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { ROLE_LABEL } from "./shared";

// Server cap on one chat message (team_validate_action, 0073).
const MAX_MESSAGE = 4000;

const timeOf = (iso?: string) => {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

// ── G-13: team chat — the war-room channel, always visible (not folded away) ──
// Oldest → newest like any chat, auto-scrolls to the latest message, and flags
// messages from teammates that arrived while you were busy elsewhere.
export function WarRoom({ events, me, nameOf, act }: { events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const msgs = useMemo(() => events.filter(e => e.type === "message.sent"), [events]);
  const fromOthers = useMemo(() => msgs.filter(e => e.actor_id !== me.id).length, [msgs, me.id]);
  const [seen, setSeen] = useState(fromOthers);
  const unread = Math.max(0, fromOthers - seen);
  const listRef = useRef<HTMLDivElement>(null);
  const canWrite = !!(me.role && me.role !== "observer");
  const canPost = canWrite && msg.trim().length > 0 && msg.trim().length <= MAX_MESSAGE;

  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [msgs.length]);
  // The message list is a polite live log, switched on only after the chat history
  // has loaded — so screen readers hear NEW messages, not the whole backlog.
  const [liveLog, setLiveLog] = useState(false);
  useEffect(() => { const t = setTimeout(() => setLiveLog(true), 2000); return () => clearTimeout(t); }, []);

  async function send() {
    if (!canPost || busy) return;
    setBusy(true); setFailed(false);
    const ok = await act("message.sent", { text: msg.trim() });
    setBusy(false);
    if (ok) { setMsg(""); setSeen(fromOthers); } else setFailed(true);
  }

  return (
    <Card className={`border-cyber-500/40 transition-shadow ${unread > 0 ? "shadow-[0_0_0_1px_rgba(34,211,238,0.35),0_0_24px_-6px_rgba(34,211,238,0.45)]" : ""}`}>
      <div onClick={() => setSeen(fromOthers)}>
        <div className="mb-2 flex items-center gap-2">
          <MessagesSquare className="h-4 w-4 text-cyber-300" aria-hidden="true" />
          <h3 id="team-chat-heading" className="text-sm font-bold text-white">Team chat</h3>
          {unread > 0 && (
            <span className="rounded-full bg-cyber-500 px-1.5 py-px text-[10px] font-bold text-bg">{unread} new</span>
          )}
          <span className="ml-auto text-[10px] text-slate-500">Everyone on the team sees this · {msgs.length} {msgs.length === 1 ? "message" : "messages"}</span>
        </div>

        <div ref={listRef} role="log" aria-live={liveLog ? "polite" : "off"} aria-relevant="additions" aria-labelledby="team-chat-heading" className="mb-2 max-h-72 min-h-[5rem] space-y-2 overflow-y-auto rounded-lg border border-border/60 bg-bg/60 p-2">
          {msgs.length === 0 ? (
            <p className="py-4 text-center text-xs text-slate-500">No messages yet. Coordinate here: ask for context, call out what you found, hand off work.</p>
          ) : msgs.map(e => {
            const mine = e.actor_id === me.id;
            const role = e.role ? (ROLE_LABEL[e.role] ?? e.role) : "";
            return (
              <div key={e.seq} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded-lg px-2.5 py-1.5 ${mine ? "bg-cyber-500/15 border border-cyber-500/30" : "bg-bg-elevated border border-border/60"}`}>
                  <p className="mb-0.5 flex flex-wrap items-center gap-x-1.5 text-[10px]">
                    <bdi className="font-semibold text-slate-200">{mine ? "You" : nameOf(e.actor_id)}</bdi>
                    {role && <span className="text-cyber-300/80">{role}</span>}
                    <span className="text-slate-500">{timeOf(e.occurred_at)}</span>
                  </p>
                  <p dir="auto" className="whitespace-pre-wrap break-words text-xs text-slate-200">{asStr((e.payload as { text?: string }).text)}</p>
                </div>
              </div>
            );
          })}
        </div>

        {canWrite ? (
          <div className="flex items-end gap-2">
            <textarea
              id="team-chat-input"
              value={msg}
              onChange={e => setMsg(e.target.value)}
              onFocus={() => setSeen(fromOthers)}
              onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(); } }}
              placeholder="Message the team… (Enter to send, Shift+Enter for a new line)"
              rows={2}
              aria-label="Message the team"
              dir="auto"
              className="min-h-[2.5rem] flex-1 resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none"
            />
            <Button variant="primary" size="sm" disabled={busy || !canPost} onClick={() => void send()}><Send className="mr-1 h-3.5 w-3.5" /> Send</Button>
          </div>
        ) : (
          <p className="text-[11px] text-slate-500">Observers can read the chat but not post.</p>
        )}
        {msg.trim().length > MAX_MESSAGE - 300 && (
          <p className={`mt-1 text-[10px] ${msg.trim().length > MAX_MESSAGE ? "text-severity-high" : "text-slate-500"}`}>
            {msg.trim().length}/{MAX_MESSAGE} characters in one message{msg.trim().length > MAX_MESSAGE ? " — split it into two messages" : ""}
          </p>
        )}
        {failed && <p className="mt-1 text-[10px] text-severity-high">The message wasn&apos;t sent. Check your connection and press Send again.</p>}
      </div>
    </Card>
  );
}
