"use client";
import { useState, useMemo, useEffect, useRef } from "react";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ChevronDown, ChevronUp, MessagesSquare, Send } from "lucide-react";
import type { Me, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { ROLE_LABEL } from "./shared";
import { AttachImageButton, PendingImages, TeamImageThumb, imagesOf, uploadTeamImage, useImageAttachments } from "./teamImages";

// Server cap on one chat message (team_validate_action, 0073).
const MAX_MESSAGE = 4000;
/** Text sent with an image that has no caption (the message itself must not be empty). */
const IMAGE_ONLY_TEXT = "Shared a screenshot";

const timeOf = (iso?: string) => {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
};

// ── G-13: team chat — the war-room channel ──
// Oldest → newest like any chat, auto-scrolls its own list to the latest message, and flags
// messages from teammates that arrived while you were busy elsewhere. Screenshots can
// be pasted (Ctrl+V), dropped, or attached with the image button.
// 2026-10-08 (Tal: "the chat jumped over the log"): it lives in the role column, not under the
// feed, and folds to a one-line bar (last message + unread count). A new message never opens
// it or moves anything; it only lights the badge. Open/closed is remembered per session.
export function WarRoom({ sessionId, events, me, nameOf, act }: { sessionId: string; events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const att = useImageAttachments(1);
  const msgs = useMemo(() => events.filter(e => e.type === "message.sent"), [events]);
  const fromOthers = useMemo(() => msgs.filter(e => e.actor_id !== me.id).length, [msgs, me.id]);
  const [seen, setSeen] = useState(fromOthers);
  const unread = Math.max(0, fromOthers - seen);
  const listRef = useRef<HTMLDivElement>(null);
  const canWrite = !!(me.role && me.role !== "observer");
  const canPost = canWrite && (msg.trim().length > 0 || att.items.length > 0) && msg.trim().length <= MAX_MESSAGE;
  const openKey = `team-chat-open:${sessionId}`;
  const [open, setOpen] = useState(true);
  useEffect(() => { try { const v = localStorage.getItem(openKey); if (v !== null) setOpen(v === "1"); } catch { /* storage blocked */ } }, [openKey]);
  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next) setSeen(fromOthers);
    try { localStorage.setItem(openKey, next ? "1" : "0"); } catch { /* storage blocked */ }
  };
  const last = msgs[msgs.length - 1];
  const lastText = last ? (asStr((last.payload as { text?: unknown }).text) || IMAGE_ONLY_TEXT) : "";

  useEffect(() => {
    const el = listRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [msgs.length, open]);
  // The message list is a polite live log, switched on only after the chat history
  // has loaded — so screen readers hear NEW messages, not the whole backlog.
  const [liveLog, setLiveLog] = useState(false);
  useEffect(() => { const t = setTimeout(() => setLiveLog(true), 2000); return () => clearTimeout(t); }, []);

  async function send() {
    if (!canPost || busy) return;
    setBusy(true); setFailed(false); att.setError(null);
    let image: Awaited<ReturnType<typeof uploadTeamImage>> | undefined;
    if (att.items[0]) {
      try { image = await uploadTeamImage(sessionId, att.items[0]); }
      catch (e) { setBusy(false); att.setError(e instanceof Error ? e.message : "The image couldn't be uploaded."); return; }
    }
    const ok = await act("message.sent", { text: msg.trim() || IMAGE_ONLY_TEXT, ...(image ? { image } : {}) });
    setBusy(false);
    if (ok) { setMsg(""); att.clear(); setSeen(fromOthers); } else setFailed(true);
  }

  return (
    <Card className={`border-cyber-500/40 transition-shadow ${unread > 0 ? "shadow-[0_0_0_1px_rgba(34,211,238,0.35),0_0_24px_-6px_rgba(34,211,238,0.45)]" : ""}`}>
      <div onClick={() => open && setSeen(fromOthers)} {...(canWrite && open ? att.dropProps : {})}>
        <button type="button" onClick={e => { e.stopPropagation(); toggle(); }} aria-expanded={open} aria-controls="team-chat-body"
          className={`flex w-full items-center gap-2 rounded-md text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-cyber-400 ${open ? "mb-2" : ""}`}>
          <MessagesSquare className="h-4 w-4 shrink-0 text-cyber-300" aria-hidden="true" />
          <h3 id="team-chat-heading" className="shrink-0 text-sm font-bold text-white">Team chat</h3>
          {unread > 0 && (
            <span className="shrink-0 rounded-full bg-cyber-500 px-1.5 py-px text-[10px] font-bold text-bg">{unread} new</span>
          )}
          {open
            ? <span className="ml-auto truncate text-[10px] text-slate-500">Everyone on the team sees this · {msgs.length} {msgs.length === 1 ? "message" : "messages"}</span>
            : <span className="ml-1 min-w-0 flex-1 truncate text-[11px] text-slate-400">{last ? <><bdi className="text-slate-300">{last.actor_id === me.id ? "You" : nameOf(last.actor_id)}:</bdi> <span dir="auto">{lastText}</span></> : "No messages yet"}</span>}
          {open ? <ChevronUp className="ml-1 h-4 w-4 shrink-0 text-slate-400" aria-hidden /> : <ChevronDown className="ml-auto h-4 w-4 shrink-0 text-slate-400" aria-hidden />}
          <span className="sr-only">{open ? "Collapse the team chat" : "Open the team chat"}</span>
        </button>

        <div id="team-chat-body" hidden={!open}>
        <div ref={listRef} role="log" aria-live={liveLog && open ? "polite" : "off"} aria-relevant="additions" aria-labelledby="team-chat-heading" className="mb-2 max-h-56 min-h-[4rem] space-y-2 overflow-y-auto overscroll-contain rounded-lg border border-border/60 bg-bg/60 p-2">
          {msgs.length === 0 ? (
            <p className="py-4 text-center text-xs text-slate-500">No messages yet. Coordinate here: ask for context, call out what you found, hand off work, paste a screenshot.</p>
          ) : msgs.map(e => {
            const mine = e.actor_id === me.id;
            const role = e.role ? (ROLE_LABEL[e.role] ?? e.role) : "";
            const p = e.payload as { text?: string; image?: unknown };
            const text = asStr(p.text);
            const img = imagesOf(p.image)[0];
            const caption = img && text !== IMAGE_ONLY_TEXT ? text : "";
            const who = mine ? "you" : nameOf(e.actor_id);
            return (
              <div key={e.seq} className={`flex ${mine ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[85%] rounded-lg px-2.5 py-1.5 ${mine ? "bg-cyber-500/15 border border-cyber-500/30" : "bg-bg-elevated border border-border/60"}`}>
                  <p className="mb-0.5 flex flex-wrap items-center gap-x-1.5 text-[10px]">
                    <bdi className="font-semibold text-slate-200">{mine ? "You" : nameOf(e.actor_id)}</bdi>
                    {role && <span className="text-cyber-300/80">{role}</span>}
                    <span className="text-slate-500">{timeOf(e.occurred_at)}</span>
                  </p>
                  {img && <div className="mt-0.5"><TeamImageThumb sessionId={sessionId} image={img} alt={caption || `Screenshot shared by ${who}`} /></div>}
                  {(!img || caption) && <p dir="auto" className={`whitespace-pre-wrap break-words text-xs text-slate-200 ${img ? "mt-1" : ""}`}>{text}</p>}
                </div>
              </div>
            );
          })}
        </div>

        {canWrite && att.items.length > 0 && (
          <div className="mb-2 rounded-lg border border-border/60 bg-bg/60 p-2">
            <PendingImages items={att.items} onRemove={att.remove} />
            <p className="mt-1 text-[11px] text-slate-400">Image ready. Add a caption if you like, then press Send.</p>
          </div>
        )}
        {canWrite ? (
          <div className="flex items-end gap-2">
            <AttachImageButton onPick={f => void att.add(f)} />
            <textarea
              id="team-chat-input"
              value={msg}
              onChange={e => setMsg(e.target.value)}
              onFocus={() => setSeen(fromOthers)}
              onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void send(); } }}
              onPaste={att.onPaste}
              placeholder="Message the team… (Enter to send · paste a screenshot with Ctrl+V)"
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
        {att.error && <p role="alert" className="mt-1 text-[10px] text-severity-high">{att.error}</p>}
        </div>
      </div>
    </Card>
  );
}
