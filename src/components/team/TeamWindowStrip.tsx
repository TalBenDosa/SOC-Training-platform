"use client";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import type { Ev, Me, RosterMember } from "@/lib/team/types";
import { showSiemWindow } from "@/lib/team/twoWindows";
import { chatReadKey, titleWithCount, waitingCounts, type WaitingCounts } from "@/lib/team/teamWindowCounts";
import { ISOLATION_REQUEST_TYPES } from "@/lib/team/isolationApproval";

/** How often the strip re-reads the team's coordination events. */
export const STRIP_POLL_MS = 8_000;
const TYPES = ["escalation.requested", "escalation.acknowledged", "escalation.bounced", "escalation.resolved", "message.sent",
  "containment.requested", "containment.approved", "containment.denied", "containment.executed", ...ISOLATION_REQUEST_TYPES];

/**
 * The thin strip at the top of the Sentinel window (2026-11 review: in Sentinel the analyst did not see
 * waiting escalations, chat or approvals). Three counts, each a link that brings the team room (the SIEM
 * window) forward, plus the same count in this tab's title. Read-only: it never acts.
 */
export function TeamWindowStrip({ sessionId }: { sessionId: string }) {
  const [events, setEvents] = useState<Ev[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [roster, setRoster] = useState<(RosterMember & { active?: boolean })[]>([]);
  const [readSeq, setReadSeq] = useState(0);
  const maxSeq = useRef(0);

  const pull = useCallback(async () => {
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    const { data } = await sb.from("session_events").select("seq, type, actor_id, role, payload, occurred_at")
      .eq("session_id", sessionId).in("type", TYPES).gt("seq", maxSeq.current).order("seq").limit(1000);
    if (data?.length) {
      maxSeq.current = (data[data.length - 1] as Ev).seq;
      setEvents(prev => [...prev, ...(data as Ev[])]);
    }
  }, [sessionId]);
  useEffect(() => {
    let alive = true;
    const loadMeta = () => fetch(`/api/team/sessions/${sessionId}`).then(r => (r.ok ? r.json() : null)).then(d => { if (alive && d) { setMe(d.me ?? null); setRoster(d.roster ?? []); } }).catch(() => {});
    void loadMeta(); void pull();
    const iv = setInterval(() => { void pull(); }, STRIP_POLL_MS);
    const meta = setInterval(() => { void loadMeta(); }, 60_000);   // who is active (the approver rule)
    return () => { alive = false; clearInterval(iv); clearInterval(meta); };
  }, [sessionId, pull]);
  // The team room records the last chat message the player saw (same browser): read it live.
  useEffect(() => {
    if (!me) return;
    const key = chatReadKey(sessionId, me.id);
    const read = () => { try { setReadSeq(Number(localStorage.getItem(key) ?? 0) || 0); } catch { /* storage blocked */ } };
    read();
    const onStorage = (e: StorageEvent) => { if (e.key === key) read(); };
    window.addEventListener("storage", onStorage);
    window.addEventListener("focus", read);
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener("focus", read); };
  }, [sessionId, me]);

  const counts: WaitingCounts | null = useMemo(() => {
    if (!me) return null;
    const members = roster.map(m => ({ user_id: m.user_id, role: m.role, status: m.status, active: m.active ?? true }));
    return waitingCounts(events, { meId: me.id, role: me.role, isStaff: me.is_staff, members, chatReadSeq: readSeq });
  }, [events, me, roster, readSeq]);
  const total = counts ? counts.escalations + counts.unreadChat + counts.approved + counts.approvals : 0;
  useEffect(() => {
    document.title = titleWithCount(document.title, total);
    return () => { document.title = titleWithCount(document.title, 0); };
  }, [total]);

  if (!counts) return null;
  const back = () => showSiemWindow(sessionId, `/team/${sessionId}`);
  const items: { n: number; one: string; many: string; tone: string }[] = [
    { n: counts.escalations, one: "escalation waiting", many: "escalations waiting", tone: "#ffb900" },
    { n: counts.unreadChat, one: "unread chat message", many: "unread chat messages", tone: "#0078d4" },
    { n: counts.approved, one: "containment approved: carry it out", many: "containments approved: carry them out", tone: "#107c10" },
    { n: counts.approvals, one: "request waits for your approval", many: "requests wait for your approval", tone: "#d13438" },
  ];
  return (
    <nav aria-label="Team room" data-testid="team-window-strip"
      style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "4px 14px", padding: "3px 12px", fontSize: 12, lineHeight: "18px", borderBottom: "1px solid #e1dfdd", background: "#faf9f8", color: "#323130" }}>
      <span style={{ fontWeight: 600 }}>Team room</span>
      {total === 0 ? <span style={{ color: "#605e5c" }}>Nothing waiting for you there.</span> : items.filter(i => i.n > 0).map(i => (
        <button key={i.one} type="button" onClick={back}
          style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "none", border: 0, padding: 0, cursor: "pointer", color: "#0f6cbd", textDecoration: "underline", font: "inherit" }}>
          <span aria-hidden style={{ width: 7, height: 7, borderRadius: 999, background: i.tone, display: "inline-block" }} />
          {i.n} {i.n === 1 ? i.one : i.many}
        </button>
      ))}
      <span style={{ marginLeft: "auto", color: "#605e5c" }}>Each link opens the team room window.</span>
    </nav>
  );
}
