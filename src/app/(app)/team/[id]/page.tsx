"use client";
/**
 * Team-SOC lobby + exercise room (Phase 0.4).
 *
 * LOBBY: live presence + ready-check (§13.11).
 * RUNNING: the shared real-telemetry feed (identical for everyone — driven by
 * pg_cron + Broadcast-from-Database, with a DB reconcile safety-net so no member
 * ever misses a log) PLUS role consoles: T1 dispositions + structured escalation,
 * T2/T3 escalation inbox → acknowledge → request containment, Lead approve/deny.
 * Every action is an apply_session_action event, so the whole team sees the same
 * incident AND the same coordination, live.
 */
import { useEffect, useRef, useState, useCallback, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import type { RealtimeChannel } from "@supabase/supabase-js";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { usePageTitle } from "@/lib/hooks/usePageTitle";
import { getSupabaseBrowserClient } from "@/lib/supabase/client";
import { EventFeed } from "@/app/(app)/dashboard/EventFeed";
import { ItVerifyContext, type TeamItVerifier } from "@/app/(app)/dashboard/itVerifyContext";
import { EscalateCopyContext } from "@/app/(app)/dashboard/escalateCopyContext";
import { EdrPivotContext, type EdrPivot } from "@/app/(app)/dashboard/edrPivotContext";
import { OpenCaseModal } from "./_components/OpenCaseModal";
import { enrichEvent, severityBase, type LiveEvent } from "@/app/(app)/dashboard/liveEventEnrich";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildTeamEdrCases } from "@/lib/edr/teamCases";
import { useTeamIocTruth } from "@/lib/team/useTeamIocTruth";
import { IocTruthContext } from "@/components/threat-intel/iocTruthContext";
import { Loader2, AlertTriangle, CheckCircle2, Circle, Radio, Play, ShieldCheck, ArrowLeft, Users, Siren, X, UserMinus, PauseCircle, LogOut, Cpu } from "lucide-react";
import type { RosterMember, SessionMeta, Me, Ev, Ioc } from "@/lib/team/types";
import { asStr, detectIocType, friendlyActionError, hashString, actionErrorCode, hostKey, type ActOutcome, type ActionErrorCode } from "@/lib/team/format";
import { deriveReadyMap } from "@/lib/team/lobbyReady";
import { withRebasedTime } from "@/lib/sim/rebaseTime";
import { useTeamHeartbeat } from "@/lib/team/useTeamHeartbeat";
import { calibrateFromDateHeader, noteServerTimestamp, useServerNow } from "@/lib/team/clock";
import { buildAlertQueue, nextAlertFor } from "@/lib/team/alertQueue";
import { teamLoad, type Difficulty } from "@/lib/team/load";
import { loadWithPlan } from "@/lib/team/attackPlan";
import { activeClaims, escalationStates, containmentRequests, scopeByIncident, latestScope, incidentLabels, incidentByEvent, openLoadByUser } from "@/lib/team/projections";
import { pausedSpans } from "@/lib/team/pauses";
import { PRODUCT_LABEL, STACK_CHOICES } from "@/lib/logs/native/stack";
import { INDUSTRY_CHOICES, PLATFORM_CHOICES } from "@/lib/team/environment";
import { advanceWatermark } from "@/lib/team/eventLog";
import { ROLE_LABEL } from "./_components/shared";
import { roleDirective, RoleGuideModal } from "./_components/RoleGuideModal";
import { SharedCase } from "./_components/SharedCase";
import { T1Console } from "./_components/T1Console";
import { T2Console } from "./_components/T2Console";
import { LeadConsole } from "./_components/LeadConsole";
import { AddMemberPanel } from "./_components/AddMemberPanel";
import { InstructorPanel } from "./_components/InstructorPanel";
import { RemoveMemberButton } from "./_components/RemoveMemberButton";
import { InjectFeed } from "./_components/InjectFeed";
import { HuntConsole } from "./_components/HuntConsole";
import { DEConsole } from "./_components/DEConsole";
import { TIConsole } from "./_components/TIConsole";
import { MgrConsole } from "./_components/MgrConsole";
import { TeamReport } from "./_components/TeamReport";
import { FeedFilterBar } from "./_components/FeedFilterBar";
import { SituationBoard } from "./_components/SituationBoard";
import { SecondaryPanels } from "./_components/SecondaryPanels";
import { WarRoom } from "./_components/WarRoom";
import { TeamIntel } from "./_components/TeamIntel";
import { NativeLogProvider, type NativeRenderer } from "@/lib/logs/native/NativeLogContext";

const OPEN_CASE_COPY = { title: "Open a case on this log", hint: "You found it: start the case yourself and own it" };

export default function TeamRoomPage() {
  const { id } = useParams<{ id: string }>();
  // "Verify with IT": the log carries no answer key, so IT's reply comes from the server.
  const itVerify = useCallback<TeamItVerifier>(async (eventId) => {
    const r = await fetch(`/api/team/sessions/${id}/it-verify`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event_id: eventId }) });
    if (!r.ok) throw new Error(`it-verify ${r.status}`);
    return r.json();
  }, [id]);
  usePageTitle("Team session");

  const [session, setSession] = useState<SessionMeta | null>(null);
  const [roster, setRoster] = useState<RosterMember[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // QA M1: the server says I was removed from this session (403 { removed }) — the room is closed to me.
  const [removed, setRemoved] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [edrNote, setEdrNote] = useState<string | null>(null); // B8: EDR open feedback (shown in any phase, incl. running)

  const [online, setOnline] = useState<Set<string>>(new Set());
  // Lobby readiness is DERIVED from the server's event log (+ the roster status at load) — see
  // readyMap below. Presence used to overwrite it on every sync with each client's own tracked
  // flag (m[0].ready — often stale or not yet updated), so a ready mark vanished whenever anyone
  // joined or clicked and players had to click again (prod logs: repeated member.ready per user).
  const [pendingReady, setPendingReady] = useState<boolean | null>(null);
  // P5-10: presence re-tracks on every (re)subscribe. It must send MY CURRENT
  // ready state — the subscribe callback is created once, so reading the roster
  // there sent the state from page load and flipped the lobby back on reconnect.
  const [phase, setPhase] = useState<"lobby" | "running" | "ended">("lobby");
  const [countdown, setCountdown] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  // event log (ALL types), deduped by seq
  const [events, setEvents] = useState<Ev[]>([]);
  const [dismissedNudgeSeq, setDismissedNudgeSeq] = useState(0); // latest rebalance-nudge the viewer closed
  const [showGuide, setShowGuide] = useState(false);
  // Session-lifecycle UX: who just left (transient popups), whether staff has
  // temporarily dismissed the "training halted" overlay to reassign/end, and why
  // the session closed (for the ended screen).
  const [leftNotices, setLeftNotices] = useState<{ key: string; name: string; role: string }[]>([]);
  const [haltDismissed, setHaltDismissed] = useState(false);
  const [endReason, setEndReason] = useState<string | null>(null);
  // DB-persisted pause (survives reload, shows as 'paused' in the list). Distinct
  // from the presence-derived halt, which is what DRIVES the auto pause/resume.
  const [paused, setPaused] = useState(false);
  const [pausedReason, setPausedReason] = useState<string | null>(null);
  const [pausedDetail, setPausedDetail] = useState<string | null>(null);
  const [haltConfirmed, setHaltConfirmed] = useState(false); // coverage broken past the debounce
  const haltTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const prevOnlineRef = useRef<Set<string>>(new Set());
  const ownerGoneTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const autoEndFiredRef = useRef(false);
  // Realtime-health signals so the DB reconcile pull only runs when realtime is
  // down/silent (scale: the pull is otherwise O(online users) queries forever).
  const lastRealtimeAtRef = useRef(0);
  const channelHealthyRef = useRef(false);
  const autoPauseBusyRef = useRef(false);
  const countdownIvRef = useRef<ReturnType<typeof setInterval> | null>(null);
  // G-04 feed filters (surfaced controls + click-to-pivot state).
  const [fSeverity, setFSeverity] = useState<"all" | "low" | "medium" | "high">("all");
  const [fSource, setFSource] = useState("all");
  const [fSearch, setFSearch] = useState("");
  const [fUser, setFUser] = useState("all");
  const [fHost, setFHost] = useState("all");
  const [fIp, setFIp] = useState("all");
  const [iocDraft, setIocDraft] = useState<Ioc[]>([]); // T1-5: shared IOC clipboard (feed "+IOC" → T1 report)
  // T1 log-anchored escalation: the selected event id + whether the report modal is open.
  // Lifted here so the 🚩 button on a LOG (feed DetailPanel) can drive T1Console's report.
  const [t1Sel, setT1Sel] = useState<string>("");
  // Tier-1 queue = a VIEW of the SIEM table ("Needs triage"), not a separate card.
  const [feedView, setFeedView] = useState<"all" | "triage">("all");
  const [queueWithMedium, setQueueWithMedium] = useState(false);
  const [pulledNote, setPulledNote] = useState<string | null>(null);
  useEffect(() => { if (!pulledNote) return; const t = setTimeout(() => setPulledNote(null), 4000); return () => clearTimeout(t); }, [pulledNote]);
  const [t1ReportOpen, setT1ReportOpen] = useState(false);
  // QA M4: the logs this analyst has opened — threat intel is only looked up for IOCs in hand.
  const [openedIds, setOpenedIds] = useState<Set<string>>(() => new Set());
  const markOpened = useCallback((eid?: string) => {
    if (!eid) return;
    setOpenedIds(prev => (prev.has(eid) ? prev : new Set(prev).add(eid)));
  }, []);
  const seqSeen = useRef<Set<number>>(new Set());
  const maxSeqRef = useRef(0);
  // C1: contiguous watermark — every seq ≤ it has been seen. The pull cursor is this
  // (not the max), so a missed broadcast below the head is re-fetched, never lost.
  const contigRef = useRef(0);
  const pullRef = useRef<(() => Promise<void>) | null>(null);
  const gapTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const channelRef = useRef<RealtimeChannel | null>(null);
  // C6: connection health for the "Live / Reconnecting / Degraded" pill.
  const [socketLive, setSocketLive] = useState(false);
  const [pullHealthy, setPullHealthy] = useState(true);
  const errorTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const nameOf = useCallback((uid: string | null) => uid ? (roster.find(r => r.user_id === uid)?.name ?? uid.slice(0, 8)) : "system", [roster]);

  // Friendly, auto-clearing error banner (C6).
  const showError = useCallback((msg: string) => {
    setError(msg);
    if (errorTimerRef.current) clearTimeout(errorTimerRef.current);
    errorTimerRef.current = setTimeout(() => setError(e => (e === msg ? null : e)), 8000);
  }, []);
  useEffect(() => () => { if (errorTimerRef.current) clearTimeout(errorTimerRef.current); }, []);

  const requestPull = useCallback((delay = 300) => {
    if (gapTimerRef.current) return;                     // debounce: one pull per burst
    gapTimerRef.current = setTimeout(() => { gapTimerRef.current = null; void pullRef.current?.(); }, delay);
  }, []);
  useEffect(() => () => { if (gapTimerRef.current) clearTimeout(gapTimerRef.current); }, []);

  const mergeEvents = useCallback((incoming: Ev[]) => {
    const fresh = incoming.filter(e => typeof e.seq === "number" && !seqSeen.current.has(e.seq));
    if (fresh.length === 0) return;
    fresh.forEach(e => { seqSeen.current.add(e.seq); if (e.seq > maxSeqRef.current) maxSeqRef.current = e.seq; });
    contigRef.current = advanceWatermark(seqSeen.current, contigRef.current);
    if (maxSeqRef.current > contigRef.current) requestPull();   // a hole below the head → fill it
    setEvents(prev => [...prev, ...fresh].sort((a, b) => a.seq - b.seq));
  }, [requestPull]);

  const startCountdown = useCallback(() => {
    if (countdownIvRef.current) return; // already counting down (start() + our own session.started broadcast)
    setCountdown(3);
    let n = 3;
    countdownIvRef.current = setInterval(() => {
      n -= 1;
      if (n <= 0) { if (countdownIvRef.current) clearInterval(countdownIvRef.current); countdownIvRef.current = null; setCountdown(null); setPhase("running"); }
      else setCountdown(n);
    }, 1000);
  }, []);
  // Clear the countdown interval on unmount so it can't setState on a dead tree.
  useEffect(() => () => { if (countdownIvRef.current) clearInterval(countdownIvRef.current); }, []);

  // ── initial load ──────────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const sentAt = Date.now();
      // P5-07: a network drop used to throw here and leave "Loading…" forever.
      const res = await fetch(`/api/team/sessions/${id}`).catch(() => null);
      if (!res) { if (!cancelled) { setError("Couldn't reach the server — check your connection and reload."); setLoading(false); } return; }
      calibrateFromDateHeader(res.headers.get("date"), sentAt, Date.now());   // C5: server clock offset
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (!cancelled) { if (body?.removed) setRemoved(body.error ?? "You were removed from this session."); else setError(body?.error ?? "Failed to load."); setLoading(false); }
        return;
      }
      const data = await res.json();
      if (cancelled) return;
      setSession(data.session); setRoster(data.roster); setMe(data.me);
      // A session paused AFTER it started resumes into the running screen (blocked
      // by the halt overlay); paused-before-start stays in the lobby.
      const st = data.session.status as string;
      const started = !!data.session.started_at;
      setPhase(st === "running" ? "running" : st === "paused" ? (started ? "running" : "lobby") : st === "lobby" ? "lobby" : "ended");
      setPaused(st === "paused" && started);
      if (st === "paused" && started) { setPausedReason(data.session.pause_reason ?? null); setPausedDetail(data.session.pause_detail ?? null); }
      setLoading(false);
    })();
    return () => { cancelled = true; };
  }, [id]);

  // First-use role guide: pop it once per role when the exercise goes live.
  useEffect(() => {
    if (phase !== "running" || !me?.role) return;
    try {
      const key = `team-guide-seen-${me.role}`;
      if (!localStorage.getItem(key)) { setShowGuide(true); localStorage.setItem(key, "1"); }
    } catch { /* private mode — just skip the auto-popup */ }
  }, [phase, me?.role]);

  // ── event log sync: initial load + gap-filling reconcile, in EVERY phase ──
  //    Lobby too (C2): a client that missed the one session.started broadcast used
  //    to sit in the lobby while the shift ran. The cursor is the contiguous
  //    watermark (C1), so any hole below the head is re-fetched.
  useEffect(() => {
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let stop = false;
    let failures = 0;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const pull = async () => {
      // Paginate by seq cursor in 1000-row pages (PostgREST caps a single query at ~1000 rows).
      let cursor = contigRef.current;
      try {
        for (let guard = 0; guard < 60 && !stop; guard++) {
          const { data, error: pullErr } = await sb.from("session_events").select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", id).gt("seq", cursor).order("seq").limit(1000);
          if (pullErr) throw pullErr;
          if (stop || !data || data.length === 0) break;
          mergeEvents(data as Ev[]);
          cursor = (data[data.length - 1] as Ev).seq;
          if (data.length < 1000) break;
        }
        failures = 0; setPullHealthy(true);
      } catch {
        failures++; setPullHealthy(false);
      }
    };
    pullRef.current = pull;
    void pull();
    if (phase === "ended") return () => { stop = true; if (pullRef.current === pull) pullRef.current = null; };
    // Realtime broadcast is the primary delivery. Reconcile from the DB only when the
    // channel is unhealthy, silent for a while, or a gap is known — plus a slow lobby
    // poll for session.started. Exponential backoff + jitter so a realtime outage
    // doesn't make every client poll in lockstep.
    const schedule = () => {
      const base = phase === "lobby" ? 15000 : 10000;
      const delay = Math.min(60000, base * 2 ** failures) * (0.8 + Math.random() * 0.4);
      timer = setTimeout(async () => {
        if (stop) return;
        const needs = phase === "lobby" || !channelHealthyRef.current
          || Date.now() - lastRealtimeAtRef.current > 25000 || contigRef.current < maxSeqRef.current;
        if (needs) await pull();
        schedule();
      }, delay);
    };
    schedule();
    const onVisible = () => { if (document.visibilityState === "visible") void pull(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      stop = true;
      if (timer) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisible);
      if (pullRef.current === pull) pullRef.current = null;
    };
  }, [phase, id, mergeEvents]);

  // ── realtime: presence + broadcast ─────────────────────────────────────────
  useEffect(() => {
    if (!me) return;
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let cancelled = false;
    let createdChannel: RealtimeChannel | null = null;
    // C5: keep the realtime socket's JWT fresh — a ~1h token expiry would otherwise
    // silently drop this client from presence and trip false coverage/owner halts.
    const { data: authSub } = sb.auth.onAuthStateChange((_evt, session) => {
      const t = session?.access_token;
      if (t) { try { sb.realtime.setAuth(t); } catch { /* socket not ready yet */ } }
    });
    (async () => {
      const { data: sess } = await sb.auth.getSession();
      const token = sess.session?.access_token;
      if (token) sb.realtime.setAuth(token);
      if (cancelled) return; // C4: unmounted before we got here — don't create a channel
      const channel = sb.channel(`session:${id}`, { config: { private: true, presence: { key: me.id } } });
      createdChannel = channel;
      channelRef.current = channel;
      channel
        .on("presence", { event: "sync" }, () => {
          lastRealtimeAtRef.current = Date.now(); // realtime is alive
          const state = channel.presenceState() as Record<string, { ready?: boolean }[]>;
          setOnline(new Set(Object.keys(state)));
        })
        .on("broadcast", { event: "session_event" }, ({ payload }) => {
          lastRealtimeAtRef.current = Date.now(); // realtime is alive → the reconcile pull can stay idle
          const p = payload as Ev & { actor_id?: string };
          noteServerTimestamp((p as { occurred_at?: string }).occurred_at);   // C5: tighten the server clock
          // Defence in depth (the realtime write policy is presence-only, so clients
          // can't broadcast at all): never trust a seq far beyond our log head — one
          // forged huge seq would otherwise blind the gap-fill pull for the session.
          if (typeof p.seq === "number" && maxSeqRef.current > 0 && p.seq > maxSeqRef.current + 1000) return;
          if (p.type === "session.started") { setSession(s => s ? { ...s, status: "running" } : s); startCountdown(); }
          else if (p.type === "session.ended") { setSession(s => s ? { ...s, status: "ended" } : s); setCountdown(null); setPhase("ended"); const rr = (p.payload as { reason?: string })?.reason; if (rr) setEndReason(rr); }
          else if (p.type === "session.paused") { setSession(s => s ? { ...s, status: "paused" } : s); setPaused(true); const pl = p.payload as { reason?: string; detail?: string }; setPausedReason(pl?.reason ?? "manual"); setPausedDetail(pl?.detail ?? null); }
          else if (p.type === "session.resumed") { setSession(s => s ? { ...s, status: "running" } : s); setPaused(false); setPausedReason(null); setPausedDetail(null); }
          if (typeof p.seq === "number") mergeEvents([{ seq: p.seq, type: p.type, actor_id: p.actor_id ?? null, role: p.role ?? null, payload: p.payload ?? {}, occurred_at: (p as { occurred_at?: string }).occurred_at }]);
        })
        .subscribe(async status => {
          channelHealthyRef.current = status === "SUBSCRIBED";
          setSocketLive(status === "SUBSCRIBED");
          if (status === "SUBSCRIBED") {
            lastRealtimeAtRef.current = Date.now();
            // C1: every (re)join may have missed broadcasts — fill the gap immediately.
            void pullRef.current?.();
            await channel.track({ online: true });
          }
        });
      // C4: if we unmounted while awaiting/subscribing, tear the just-created channel down now.
      if (cancelled) { sb.removeChannel(channel); if (channelRef.current === channel) channelRef.current = null; createdChannel = null; }
    })();
    return () => {
      cancelled = true;
      try { authSub?.subscription?.unsubscribe(); } catch { /* already gone */ }
      const ch = createdChannel ?? channelRef.current;
      if (ch) getSupabaseBrowserClient()?.removeChannel(ch);
      if (channelRef.current === ch) channelRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id, me?.id]);

  // ── action helper ───────────────────────────────────────────────────────────
  // I8: the SAME action repeated back-to-back within 2s (double-click) reuses its
  // key, so the server returns the first row instead of writing a duplicate. Any
  // different action in between gets a fresh key — ready → unready → ready or
  // claim → release → claim must all go through (a time-bucket key replayed them).
  const lastIntentRef = useRef<{ sig: string; key: string; at: number } | null>(null);
  // actR: the full outcome incl. the server's rejection code, so a console can
  // RECOVER (claim_held / case_owned → offer an explicit take-over). `handled` codes
  // don't raise the banner — the caller renders its own inline prompt for them.
  const actR = useCallback(async (type: string, payload: Record<string, unknown>, opts?: { handled?: ActionErrorCode[] }): Promise<ActOutcome> => {
    const sb = getSupabaseBrowserClient();
    const quiet = type === "event.opened";               // click telemetry never raises a banner
    if (!sb) { if (!quiet) showError("Not connected — reload the page."); return { ok: false, code: null }; }
    const sig = `${type}:${hashString(JSON.stringify(payload ?? {}))}`;
    const now = Date.now();
    const last = lastIntentRef.current;
    const idem = last && last.sig === sig && now - last.at < 2000
      ? last.key
      : `${sig}:${now.toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    lastIntentRef.current = { sig, key: idem, at: now };
    const { data, error: e } = await sb.rpc("apply_session_action", { p_session: id, p_type: type, p_payload: payload, p_idempotency_key: idem });
    if (e) {
      const code = actionErrorCode(e.message);
      if (!quiet && !(code && opts?.handled?.includes(code))) showError(friendlyActionError(e.message));
      return { ok: false, code, message: friendlyActionError(e.message) };
    }
    // C1: merge our own row straight away — our action must never depend on its broadcast.
    const row = data as Ev | null;
    if (row && typeof row.seq === "number") {
      mergeEvents([{ seq: row.seq, type: row.type, actor_id: row.actor_id ?? null, role: row.role ?? null, payload: row.payload ?? {}, occurred_at: row.occurred_at }]);
    }
    if (!quiet) setError(null);
    return { ok: true, code: null };
  }, [id, mergeEvents, showError]);
  // The boolean form every other caller uses (unchanged contract).
  const act = useCallback(async (type: string, payload: Record<string, unknown>) => (await actR(type, payload)).ok, [actR]);

  async function setReady(ready: boolean) {
    setBusy(true); setError(null); setPendingReady(ready);   // flip the button at once
    await act(ready ? "member.ready" : "member.unready", {}).catch(() => false);
    // actR merged the server's own row on success, so the derived readyMap already holds the
    // truth; on failure the error banner shows and the button falls back to the server state.
    setPendingReady(null); setBusy(false);
  }
  // P5-07: a rejected fetch (network drop) used to skip setBusy(false) and leave
  // Start / End / Pause disabled for the rest of a live exercise.
  const NET_ERR = "Couldn't reach the server — check your connection and try again.";
  async function start() {
    setBusy(true); setError(null);
    const res = await fetch(`/api/team/sessions/${id}/start`, { method: "POST" }).catch(() => null);
    setBusy(false);
    if (!res) { setError(NET_ERR); return; }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Could not start."); return; }
    setNote("Exercise starting…"); startCountdown();
  }
  async function end() {
    if (!confirm("End the session for the whole team and open the Shift review?")) return;
    setBusy(true); setError(null);
    const res = await fetch(`/api/team/sessions/${id}/end`, { method: "POST" }).catch(() => null);
    setBusy(false);
    if (!res) { setError(NET_ERR); return; }
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not end."); return; }
    setPhase("ended");
  }
  async function pauseSession(p: boolean) {
    setBusy(true); setError(null);
    const res = await fetch(`/api/team/sessions/${id}/pause`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused: p, reason: "manual" }) }).catch(() => null);
    setBusy(false);
    if (!res) { setError(NET_ERR); return; }
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not update the session."); return; }
    setPaused(p); setPausedReason(p ? "manual" : null); setPausedDetail(null); // optimistic; broadcast confirms for all
  }

  // ── derived ─────────────────────────────────────────────────────────────────
  // Observers watch only — they never "ready up", so they must not count toward the
  // ready-check (otherwise an observer wedges Start forever) nor the coverage set.
  const readyMap = useMemo(() => deriveReadyMap(roster, events, me, pendingReady), [roster, events, me, pendingReady]);
  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer" && r.status !== "left");   // a removed no-show never wedges Start
  const allReady = players.length > 0 && players.every(p => readyMap[p.user_id]);
  // Only the SOC Manager / Lead can send a SITREP — without one, management requests can't be answered.
  const hasManager = roster.some(r => (r.role === "mgr" || r.role === "lead") && r.status !== "left");
  const iAmPlayer = !!(me && me.role && me.role !== "instructor" && me.role !== "observer");
  const iAmReady = !!(me && readyMap[me.id]);
  const canRunSession = !!(me && (me.is_staff || me.role === "mgr")); // who may end/manage
  // QA M1 (staff view): invitees whose access to the organisation expired can never mark ready.
  const lapsedPlayers = players.filter(p => p.lapsed);
  // QA L3: the products the session runs on (the categories changed from the company's own).
  // The named organization's industry and platforms (Microsoft workplace always present).
  const envLine = session?.env ? [INDUSTRY_CHOICES.find(i => i.id === session.env!.industry)?.label, "Microsoft 365 & Windows endpoints",
    ...PLATFORM_CHOICES.filter(p => session.env!.platforms.includes(p.id)).map(p => p.label)].filter(Boolean).join(" · ") : "";
  const stackLine = STACK_CHOICES.map(c => { const v = session?.stack?.[c.category]; return v ? `${c.label}: ${PRODUCT_LABEL[v as keyof typeof PRODUCT_LABEL] ?? v}` : null; }).filter(Boolean).join(" · ");
  // v2 (migration 0071): coverage / instructor-left pauses are decided SERVER-side
  // from heartbeats; this browser only reports presence and renders the result.
  const v2 = (session?.schema_version ?? 1) >= 2;
  const beatUnstable = useTeamHeartbeat(v2 && phase !== "ended" ? id : null);

  // C3: roster/role changes arrive as member.* events — refresh roster + my role
  // live (a reassigned seat used to need every client to reload). session.started
  // also refreshes the session meta: /start is where schema_version is (re)confirmed,
  // and a lobby client holding a stale v1 meta would skip heartbeats — the server
  // tick would then pause the room as "instructor left".
  const refreshSessionMeta = useCallback(async () => {
    const res = await fetch(`/api/team/sessions/${id}`);
    if (!res.ok) {
      // M1: removed mid-session → close the room for me (the server already refuses my reads/writes).
      if (res.status === 403) { const b = await res.json().catch(() => null); if (b?.removed) setRemoved(b.error ?? "You were removed from this session."); }
      return;
    }
    const data = await res.json().catch(() => null);
    if (data?.roster) setRoster(data.roster);
    if (data?.me) setMe(data.me);
    const ver = data?.session?.schema_version;
    if (typeof ver === "number") setSession(s => s ? { ...s, schema_version: ver } : s);
  }, [id]);
  const metaChangeSeq = useMemo(() => {
    let s = 0;
    for (const e of events) if (e.type === "member.added" || e.type === "member.role_changed" || e.type === "member.removed" || e.type === "session.started") s = e.seq;
    return s;
  }, [events]);
  useEffect(() => { if (metaChangeSeq > 0) void refreshSessionMeta(); }, [metaChangeSeq, refreshSessionMeta]);

  // ── Session-lifecycle: presence-based coverage & auto-close ──────────────────
  const instructor = useMemo(() => roster.find(r => r.role === "instructor") ?? null, [roster]);
  // A content signature of who's online (presence hands us a NEW Set each sync even
  // when membership is unchanged) — used as a stable effect dep so timers aren't
  // reset on every heartbeat (C8).
  const onlineSig = useMemo(() => [...online].sort().join(","), [online]);
  // Core relay = Tier-1 (triage) → Tier-2 (investigate). If a core role is
  // ASSIGNED to the team but has nobody online, the shift can't run → halt.
  const CORE_ROLES: ("t1" | "t2")[] = ["t1", "t2"];
  // Don't evaluate coverage until presence has synced me in — otherwise the empty
  // initial online-set would false-trigger a halt the instant the run begins.
  const presenceReady = !!(me && online.has(me.id));
  const anyPlayerOnline = players.some(p => online.has(p.user_id));
  const uncoveredCore = (phase === "running" && presenceReady)
    ? CORE_ROLES.filter(r => roster.some(m => m.role === r) && !roster.some(m => m.role === r && online.has(m.user_id)))
    : [];
  const haltReason = (phase === "running" && presenceReady)
    ? (!anyPlayerOnline
        ? "Everyone has left the exercise."
        : uncoveredCore.length > 0
          ? `No ${uncoveredCore.map(r => ROLE_LABEL[r]).join(" and no ")} online right now.`
          : null)
    : null;
  // The halt overlay shows when the DB says paused OR coverage has been broken past
  // the debounce (C7) — so a quick refresh of the only Tier-N doesn't flash a
  // team-wide halt. A DB pause still shows instantly.
  // v2: only a DB pause (decided server-side) blocks the room; the local presence
  // view is shown as a soft warning instead. v1 keeps the client-debounced halt.
  const haltActive = phase === "running" && (paused || (!v2 && haltConfirmed));
  const haltMessage = paused
    ? (pausedReason === "manual" ? "Paused by the instructor."
      : pausedReason === "owner_left" ? (pausedDetail || "The instructor dropped out of the live room.")
      : (pausedDetail || "Not enough of the team is online right now."))
    : (haltReason ?? "");
  // The halt overlay is a blocking alert dialog: move focus into it when it appears
  // (no trap — it may coexist with another modal's trap; aria-modal hides the rest).
  const haltRef = useRef<HTMLDivElement>(null);
  const haltOpen = haltActive && !haltDismissed;
  useEffect(() => { if (haltOpen) haltRef.current?.focus(); }, [haltOpen]);
  // Debounce coverage loss: only confirm a halt if it persists ~12s (matches the
  // spirit of the owner-left grace). Resume/clear is immediate.
  useEffect(() => {
    if (!haltReason) {
      if (haltTimerRef.current) { clearTimeout(haltTimerRef.current); haltTimerRef.current = null; }
      setHaltConfirmed(false);
      return;
    }
    if (haltConfirmed || haltTimerRef.current) return;
    haltTimerRef.current = setTimeout(() => { haltTimerRef.current = null; setHaltConfirmed(true); }, 12000);
    return () => { if (haltTimerRef.current) { clearTimeout(haltTimerRef.current); haltTimerRef.current = null; } };
  }, [haltReason, haltConfirmed]);

  // who-just-left popups: diff the online set against the previous sync.
  useEffect(() => {
    if (phase === "ended") return;
    const cur = online, prev = prevOnlineRef.current;
    const dropped = roster.filter(m => prev.has(m.user_id) && !cur.has(m.user_id));
    if (dropped.length > 0) {
      setLeftNotices(ns => [...ns, ...dropped.map(m => ({ key: `${m.user_id}-${Date.now()}`, name: m.name, role: ROLE_LABEL[m.role] ?? m.role }))].slice(-4));
    }
    prevOnlineRef.current = new Set(cur);
  }, [online, roster, phase]);
  // auto-expire the oldest leave-popup so the stack clears itself.
  useEffect(() => {
    if (leftNotices.length === 0) return;
    const t = setTimeout(() => setLeftNotices(ns => ns.slice(1)), 8000);
    return () => clearTimeout(t);
  }, [leftNotices]);
  // when the halt clears, drop any staff "dismiss" of the overlay.
  useEffect(() => { if (!haltActive) setHaltDismissed(false); }, [haltActive]);

  // Auto pause/resume to the DB: one elected online client mirrors the presence
  // halt into a persisted 'paused' status (reason "coverage") and resumes it when
  // coverage returns. A manual pause (reason "manual") is left for a human resume.
  useEffect(() => {
    if (v2) return;   // v2: the server lifecycle tick decides — no elected browser
    if (phase !== "running" || !me || !presenceReady || autoPauseBusyRef.current) return;
    const elected = roster.filter(r => online.has(r.user_id)).map(r => r.user_id).sort()[0];
    if (elected !== me.id) return;
    // The server builds the halt text from these role codes (a member can't push
    // free text to the whole room).
    const call = async (p: boolean) => {
      autoPauseBusyRef.current = true;
      try { await fetch(`/api/team/sessions/${id}/pause`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused: p, reason: "coverage", missing: uncoveredCore, everyone: !anyPlayerOnline }) }); }
      catch { /* transient — the next presence sync retries */ }
      finally { autoPauseBusyRef.current = false; }
    };
    if (haltConfirmed && !paused) call(true);
    else if (!haltReason && paused && pausedReason === "coverage") call(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [v2, phase, me, presenceReady, roster, online, haltReason, haltConfirmed, paused, pausedReason, id]);

  // C1: reconcile lifecycle from the event log so a missed broadcast can't strand a
  // client on the wrong screen. The 6s reconcile pull merges the session.* event;
  // this then corrects phase/paused/reason to match the latest lifecycle event.
  useEffect(() => {
    let latest: Ev | null = null;
    for (const e of events) if (typeof e.type === "string" && e.type.startsWith("session.")) latest = e; // events are seq-sorted asc
    if (!latest) return;
    const pl = (latest.payload ?? {}) as { reason?: string; detail?: string };
    if (latest.type === "session.ended") {
      if (phase !== "ended") { setPhase("ended"); setCountdown(null); if (pl.reason) setEndReason(pl.reason); }
    } else if (latest.type === "session.paused") {
      if (!paused) { setPaused(true); setPausedReason(pl.reason ?? "manual"); setPausedDetail(pl.detail ?? null); }
    } else if (latest.type === "session.resumed") {
      if (paused) { setPaused(false); setPausedReason(null); setPausedDetail(null); }
    } else if (latest.type === "session.started") {
      // only if we clearly MISSED the start (no countdown running) — never cut a live countdown short.
      if (phase === "lobby" && countdown === null) setPhase("running");
    }
  }, [events, phase, paused, countdown]);

  // Owner (instructor) left the live room → PAUSE after a short grace (never end —
  // ending is irreversible, and a backgrounded tab / flaky socket can fake an
  // absence). When the instructor is back, the elected client resumes it.
  useEffect(() => {
    if (v2 || phase !== "running" || !instructor || !me) {   // v2: decided server-side from heartbeats
      if (ownerGoneTimer.current) { clearTimeout(ownerGoneTimer.current); ownerGoneTimer.current = null; }
      return;
    }
    const electedPlayer = () => roster.filter(r => r.role !== "instructor" && r.role !== "observer" && online.has(r.user_id)).map(r => r.user_id).sort()[0];
    if (online.has(instructor.user_id)) { // owner present — cancel any pending pause, lift an owner-left pause
      if (ownerGoneTimer.current) { clearTimeout(ownerGoneTimer.current); ownerGoneTimer.current = null; }
      autoEndFiredRef.current = false;
      if (paused && pausedReason === "owner_left" && electedPlayer() === me.id && !autoPauseBusyRef.current) {
        autoPauseBusyRef.current = true;
        fetch(`/api/team/sessions/${id}/pause`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused: false, reason: "owner_left" }) })
          .catch(() => {}).finally(() => { autoPauseBusyRef.current = false; });
      }
      return;
    }
    if (ownerGoneTimer.current || autoEndFiredRef.current) return;
    ownerGoneTimer.current = setTimeout(async () => {
      ownerGoneTimer.current = null;
      if (autoEndFiredRef.current || online.has(instructor.user_id)) return;
      // elect the lowest online player id so exactly one client fires the pause.
      const elected = electedPlayer();
      if (!elected || elected !== me.id) return;
      autoEndFiredRef.current = true;
      await fetch(`/api/team/sessions/${id}/pause`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused: true, reason: "owner_left" }) }).catch(() => {});
    }, 30000);
    return () => { if (ownerGoneTimer.current) { clearTimeout(ownerGoneTimer.current); ownerGoneTimer.current = null; } };
    // onlineSig (not the online Set) keeps the 30s timer from resetting on every
    // presence heartbeat — it re-runs only when membership actually changes (C8).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [v2, phase, instructor, onlineSig, me, roster, id, paused, pausedReason]);

  const feed = useMemo(() => events.filter(e => e.type === "feed.event"), [events]);
  // Help-desk tickets nobody has answered yet (Tier-1's to answer — fix 6).
  const openTickets = useMemo(() => {
    const answered = new Set(events.filter(e => e.type === "ticket.answered").map(e => String((e.payload as { ticket_seq?: unknown }).ticket_seq)));
    return events.filter(e => e.type === "staff.inject" && (e.payload as { kind?: unknown }).kind === "ticket" && !answered.has(String(e.seq))).length;
  }, [events]);
  // G-07 escalation state machine — per ROUND (a bounced/resolved log can be escalated
  // again) with the owner = first acknowledger or an explicit take-over (P0-3).
  // `escalations` = the current round of each escalated log (one inbox row per log).
  const escStates = useMemo(() => escalationStates(events), [events]);
  const escalations = useMemo(() => [...escStates.values()].filter(s => s.rounds > 0).map(s => s.request).sort((a, b) => a.seq - b.seq), [escStates]);
  // Explicit Tier-2 → Tier-3 elevations (deep hunt). A separate queue so T3 gets
  // work handed to it, not just a shared inbox.
  const elevations = useMemo(() => events.filter(e => e.type === "elevation.requested"), [events]);
  // Event-ids already escalated to Tier-3 — so T2's button shows an "escalated" state.
  const elevatedIds = useMemo(() => new Set(elevations.map(e => String((e.payload as { event_id?: string }).event_id))), [elevations]);
  // Elevations Tier-3 has TAKEN (distinct from escalation.acknowledged so the two
  // workflows don't cross-talk — C11).
  const elevAcked = useMemo(() => new Set(events.filter(e => e.type === "elevation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  // Which escalations already have a T2 incident report (§5 hard gate on resolve/containment).
  const reportedIds = useMemo(() => new Set(events.filter(e => e.type === "report.submitted").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  // A2: the filed report per case (findings/verdict/recommendation) so a T2→T3 elevation can carry it.
  const reportByEid = useMemo(() => { const m = new Map<string, { verdict?: string; findings?: string; recommendation?: string; summary?: string }>(); for (const e of events) if (e.type === "report.submitted") m.set(String((e.payload as { event_id?: string }).event_id), e.payload as { verdict?: string; findings?: string; recommendation?: string; summary?: string }); return m; }, [events]);
  // Silent-failure guard (F6): attack activity streaming and NOBODY escalated yet.
  // v2: the server emits a spoiler-free hint.nudge (the browser no longer holds the
  // answer key, and a nudge timed to one log would point at it). v1 legacy sessions
  // still carry the key in their payloads, so they keep the old client-side rule.
  const nowTick = useServerNow(15_000);
  const guidingNudge = useMemo((): string | null => {
    if (events.some(e => e.type === "escalation.requested")) return null;
    if (v2) {
      let hint: Ev | null = null;
      for (const e of events) if (e.type === "hint.nudge") hint = e;
      return hint ? (asStr((hint.payload as { text?: unknown }).text) || "Nobody has escalated anything yet — re-check the high-severity logs.") : null;
    }
    const firstAttack = feed.find(e => { const v = (e.payload as { expected_verdict?: string }).expected_verdict; return v === "tp" || v === "escalate"; });
    if (!firstAttack?.occurred_at) return null;
    const mins = Math.floor((nowTick - Date.parse(firstAttack.occurred_at)) / 60000);
    return mins >= 3 ? `High-signal activity has been in the feed for ~${mins} min with no escalation yet. Is the team watching the right log? Triage it and escalate if it's real.` : null;
  }, [feed, events, v2, nowTick]);
  // G-09 + P0-4: containment requests keyed by REQUEST seq (a new request after a
  // denial is its own pending row; approve/deny/execute apply per request).
  const containments = useMemo(() => containmentRequests(events), [events]);
  // G-10: latest working scope (T2 sets, T3 confirms). `confirmed` only while the
  // LATEST scope event is the confirmation (it used to stick after a later scope.set).
  // Per-incident scopes + incident labels power the per-incident case view.
  const scopes = useMemo(() => scopeByIncident(events), [events]);
  const scopeState = useMemo(() => { const s = latestScope(events); return s ? { hosts: s.hosts, users: s.users, techniques: s.techniques, confirmed: s.confirmed, by: s.by } : null; }, [events]);
  const incidents = useMemo(() => incidentLabels(events), [events]);
  const incidentOf = useMemo(() => incidentByEvent(events), [events]);
  const dispositions = useMemo(() => new Map(events.filter(e => e.type === "disposition.set").map(e => [String(e.payload.event_id), String(e.payload.verdict)])), [events]);
  // G-04b: per-row triage state for the shared feed badges (reflects the player's own
  // actions — claimed/dispositioned/escalated — never ground truth).
  const escalatedIds = useMemo(() => new Set(events.filter(e => e.type === "escalation.requested").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  // Threat-intel truth — built on the server, because this feed carries no answer key
  // (without it an attacker's hash / C2 looked up clean). QA M4: asked only for the IOCs
  // of the logs in this analyst's hands — the ones they opened, plus escalated cases.
  const iocInHand = useMemo(() => feed.filter(f => { const k = String((f.payload as { id?: unknown }).id ?? f.seq); return openedIds.has(k) || escalatedIds.has(k); }), [feed, openedIds, escalatedIds]);
  const iocTruth = useTeamIocTruth(id, iocInHand);
  useEffect(() => { if (t1Sel) markOpened(t1Sel); }, [t1Sel, markOpened]);   // T1Console records the open itself
  // Work-division: the latest overload nudge from the coordinator, shown to the whole
  // team so idle analysts pick up slack, until dismissed or superseded. Keyed on seq
  // (not server occurred_at) so a timestamp-parse/skew can't silently suppress it.
  const activeNudge = useMemo(() => {
    let latest: Ev | null = null;
    for (const e of events) if (e.type === "coordination.nudge") latest = e;
    if (!latest || (latest.seq ?? 0) <= dismissedNudgeSeq) return null;
    return latest;
  }, [events, dismissedNudgeSeq]);
  // A3/C5: the ONE claims projection (shared with T1 + the Situation Board), aged on
  // the server clock so a skewed laptop can't expire a teammate's claim early.
  const claimByEid = useMemo(() => activeClaims(events, nowTick), [events, nowTick]);
  // QA M3: paused time never ages an alert toward its SLA (nor a claim — activeClaims).
  const pauseSpans = useMemo(() => pausedSpans(events, nowTick), [events, nowTick]);
  // The Tier-1 alert queue — computed over the WHOLE feed (the SIEM table only renders
  // the latest 120 logs, so an old un-triaged alert used to show only in the queue).
  const alertQueue = useMemo(() => buildAlertQueue({ feed, dispositions, escalated: escalatedIds, claims: claimByEid, nowMs: nowTick, withMedium: queueWithMedium, pauses: pauseSpans }),
    [feed, dispositions, escalatedIds, claimByEid, nowTick, queueWithMedium, pauseSpans]);
  const queueByEid = useMemo(() => new Map(alertQueue.map(q => [q.eid, q])), [alertQueue]);
  const rowStatus = useCallback((rid?: string) => {
    if (!rid) return null;
    const key = rid.startsWith("ev_") ? rid.slice(3) : rid; // LiveEvent.id → sel-id scheme
    const disposed = dispositions.get(key);
    const c = claimByEid.get(key);
    const claim: "me" | "other" | undefined = c ? (c.by === me?.id ? "me" : "other") : undefined;
    const escalated = escalatedIds.has(key);
    const q = queueByEid.get(key);
    const triage = q ? { mins: q.mins, breached: q.breached, orphan: q.orphan } : undefined;
    if (!disposed && !claim && !escalated && !triage) return null;
    return { disposed, claim, escalated, triage };
  }, [dispositions, claimByEid, escalatedIds, queueByEid, me?.id]);
  const activity = useMemo(() => events.filter(e => ["escalation.requested", "escalation.acknowledged", "escalation.bounced", "escalation.resolved", "elevation.requested", "containment.requested", "containment.approved", "containment.denied", "containment.executed", "edr.host_isolated", "edr.host_released", "disposition.set", "hunt.logged", "rule.published", "intel.published", "handover.noted", "decision.logged", "sitrep.sent", "report.submitted", "evidence.pinned", "case.status_set", "case.assigned", "scope.set", "scope.confirmed", "staff.inject", "ticket.answered"].includes(e.type)), [events]);
  // The team feed rendered with the REAL dashboard EventFeed — enrich each shared
  // event into a LiveEvent so it looks and behaves exactly like the single-player
  // Live SOC dashboard (rule levels, source badges, raw formatting, threat-intel).
  // Normalise the required fields + guard each event so one malformed payload can
  // never crash the whole feed (real telemetry always has these; be defensive).
  const toLive = useCallback((e: Ev): LiveEvent => {
    const p = e.payload as Record<string, unknown>;
    const norm0 = {
      ...p,
      id: typeof p.id === "string" ? p.id : `ev_${e.seq}`,
      ts: typeof p.ts === "string" ? p.ts : (e.occurred_at ?? new Date().toISOString()),
      source: typeof p.source === "string" ? p.source : "siem",
      event_type: typeof p.event_type === "string" && p.event_type ? p.event_type : "informational",
      severity: typeof p.severity === "string" ? p.severity : "informational",
    } as unknown as TelemetryEvent;
    // Re-time every log to when it actually streamed in (raw{} shifted by the same
    // delta), like the single-player feed. Authored template dates used to set the
    // attack logs apart from the noise by date alone.
    const norm = e.occurred_at ? withRebasedTime(norm0, e.occurred_at) : norm0;
    // Keyed on the log's seq (not its position in a sliding window) so a log keeps
    // the same rule id in every view and as newer logs arrive.
    try { return enrichEvent(norm, e.seq); }
    catch { return { ...norm, ruleLevel: severityBase(String(norm.severity)), ruleId: "RULE-0000", displayDescription: asStr(p.description) || asStr(p.event_type) || "event" } as unknown as LiveEvent; }
  }, []);
  // P5-23: a log's enriched row never changes once it has arrived, so it is built
  // ONCE per seq and reused. Rebuilding all 120 rows on every session event gave
  // them new identities, which defeated the memoised (animated) feed rows.
  const liveCacheRef = useRef(new Map<number, LiveEvent>());
  const toLiveCached = useCallback((e: Ev): LiveEvent => {
    const hit = liveCacheRef.current.get(e.seq);
    if (hit) return hit;
    const built = toLive(e);
    liveCacheRef.current.set(e.seq, built);
    return built;
  }, [toLive]);
  const liveFeed = useMemo<LiveEvent[]>(() => feed.slice(-120).map(toLiveCached), [feed, toLiveCached]);
  // "Needs triage" view: the queue's logs, most urgent first, rendered as ordinary SIEM rows.
  const triageFeed = useMemo<LiveEvent[]>(() => alertQueue.map(q => toLiveCached(q.e)), [alertQueue, toLiveCached]);

  // Stable row handlers (P5-23): inline lambdas were new on every render.
  const feedRef = useRef(feed);
  feedRef.current = feed;
  const onFeedRowOpened = useCallback((eid?: string, dwellMs?: number) => {
    // I5: only the CLOSE carries the dwell the AAR uses; open (dwell 0) AND close — a
    // verdict given with the row still open counts as read.
    // M4: once the open is recorded, the log's IOCs may be looked up.
    void act("event.opened", { event_id: eid, dwell_ms: Math.max(0, dwellMs ?? 0) }).then(() => markOpened(eid));
  }, [act, markOpened]);
  const onFeedPivot = useCallback((field: "user" | "host" | "ip", value: string) => {
    if (field === "user") setFUser(value); else if (field === "host") setFHost(value); else setFIp(value);
  }, []);
  const onFeedAddIoc = useCallback((value: string) => {
    setIocDraft(d => d.some(x => x.value.toLowerCase() === value.toLowerCase()) ? d : [...d, { type: detectIocType(value), value, source: "picked" }]);
  }, []);
  const onFeedEscalate = useCallback((ev: LiveEvent) => {
    // Map the LiveEvent back to T1Console's sel id (same scheme as the dropdown).
    const raw = feedRef.current.find(f => {
      const p = f.payload as { id?: string };
      const lid = typeof p.id === "string" ? p.id : `ev_${f.seq}`;
      return lid === ev.id;
    });
    if (!raw) return;
    const rp = raw.payload as { id?: string };
    setT1Sel(String(rp.id ?? raw.seq));
    // Indicators are NOT auto-seeded — the analyst adds them (＋IOC on the log's
    // fields, or free text) so choosing the evidence is part of the exercise.
    setT1ReportOpen(true);
  }, []);
  // Tier-2 / Tier-3 open a case on a log they found themselves (0092).
  const [caseLog, setCaseLog] = useState<Ev | null>(null);
  const onFeedOpenCase = useCallback((ev: LiveEvent) => {
    const raw = feedRef.current.find(f => {
      const p = f.payload as { id?: string };
      return (typeof p.id === "string" ? p.id : `ev_${f.seq}`) === ev.id;
    });
    if (raw) setCaseLog(raw);
  }, []);
  const takeNextAlert = useCallback(() => {
    const next = me ? nextAlertFor(alertQueue, claimByEid, me.id) : null;
    if (!next) { setPulledNote("Nothing unclaimed right now — every open alert is being worked."); return; }
    setT1Sel(next.eid); setT1ReportOpen(true);
    setPulledNote(`Pulled #${next.e.seq} for you — it's claimed while you work it.`);
  }, [alertQueue, claimByEid, me]);
  // Distinct sources present in the feed → populate the G-04 source filter.
  const feedSources = useMemo(() => [...new Set(liveFeed.map(e => e.source).filter(Boolean))].sort(), [liveFeed]);

  // G-05: "Investigate in EDR" — reconstruct the SAME attack from the team feed's
  // endpoint telemetry (reusing the single-player builder) and deep-link into the
  // /edr console pre-loaded on the process tree. Returns null for pure identity/
  // cloud attacks with no endpoint telemetry → we tell the analyst instead of
  // opening an empty console.
  // Hosts with endpoint (EDR / Sysmon) telemetry in the feed: "Investigate in EDR" is offered
  // only for those. A case on a host the scenario has no EDR for (a DC seen only through its
  // Security log) used to show the button and answer with an error (Tal, 2026-10-08).
  const edrHosts = useMemo(() => new Set(feed
    .filter(e => { const s = (e.payload as { source?: unknown }).source; return s === "edr" || s === "sysmon"; })
    .map(e => hostKey(asStr((e.payload as { hostname?: unknown }).hostname))).filter(Boolean)), [feed]);
  const canEdr = useCallback((host?: string) => {
    if (host) return edrHosts.has(hostKey(host));
    const escHosts = escalations.map(e => asStr((e.payload as { snapshot?: { hostname?: unknown } }).snapshot?.hostname)).filter(Boolean);
    return escHosts.length ? escHosts.some(h => edrHosts.has(hostKey(h))) : edrHosts.size > 0;
  }, [edrHosts, escalations]);
  const openEdr = useCallback((description?: string, host?: string) => {
    try {
      // Same re-timing as the feed rows, so EDR shows the times the team saw.
      const evs = feed.map(e => { const t = e.payload as unknown as TelemetryEvent; return e.occurred_at ? withRebasedTime(t, e.occurred_at) : t; });
      // ONE case per host: the clicked case's host, or (console-header button) every
      // endpoint host the team escalated — never "whichever host is busiest in the feed".
      const hosts = host ? [host] : [...new Set(escalations.map(e => asStr((e.payload as { snapshot?: { hostname?: unknown } }).snapshot?.hostname)).filter(Boolean))];
      const cases = buildTeamEdrCases(evs, { sessionId: id, hosts, description, iocTruth });
      if (!cases.length) {
        setEdrNote(host
          ? `No endpoint (EDR/Sysmon) telemetry for ${host} in this shift yet — nothing to open in the EDR console.`
          : "No endpoint (EDR/Sysmon) telemetry in this incident yet — nothing to open in the EDR console.");
        return;
      }
      // B8: per-analyst key + ?u= so a second analyst opening EDR doesn't clobber the
      // first one's stashed investigation (was a shared, last-write-wins origin key).
      const uid = me?.id ?? "anon";
      localStorage.setItem(`edr_live_investigation_${uid}`, JSON.stringify(cases.length === 1 ? cases[0] : cases));
      // NOT the "noopener" feature: with it window.open() returns null even when the tab
      // DID open, which showed a false "Pop-up blocked". Cut the opener link by hand.
      const w = window.open(`/edr?case=live&team=${id}&u=${encodeURIComponent(uid)}${me?.role ? `&r=${encodeURIComponent(me.role)}` : ""}`, "_blank");
      if (!w) { setEdrNote("Pop-up blocked — allow pop-ups for this site, then click “Investigate in EDR” again."); return; }
      try { w.opener = null; } catch { /* cross-origin guard — nothing to cut */ }
      setEdrNote(null);
    } catch { setEdrNote("Couldn't open the EDR console for this incident."); }
  }, [feed, escalations, id, me?.id, me?.role, iocTruth]);

  // EDR alerts in the team feed (Tal, 2026-10-09): endpoint detections on hosts the EDR console
  // can open. They light up the "Investigate in EDR" button above the feed with a count, and a
  // NEW one pops a short corner notice (like the single-user dashboard's EDR button). An alert is
  // what the analyst's own EDR would raise, so this leaks no verdict.
  const edrAlerts = useMemo(() => feed.flatMap(e => {
    const p = e.payload as { source?: unknown; is_detection?: unknown; event_type?: unknown; hostname?: unknown; description?: unknown };
    const host = asStr(p.hostname);
    const isAlert = p.source === "edr" && (p.is_detection === true || /alert|detection|quarantine/.test(asStr(p.event_type)));
    return isAlert && host && edrHosts.has(hostKey(host)) ? [{ seq: e.seq, host, title: asStr(p.description) || "Endpoint detection" }] : [];
  }), [feed, edrHosts]);
  const edrSeen = useRef<number | null>(null);
  const [edrToast, setEdrToast] = useState<{ seq: number; host: string; title: string } | null>(null);
  useEffect(() => {
    const newest = edrAlerts[edrAlerts.length - 1];
    if (edrSeen.current === null) { edrSeen.current = newest?.seq ?? 0; return; }   // joining mid-shift: no backlog pop-ups
    if (newest && newest.seq > edrSeen.current) { edrSeen.current = newest.seq; setEdrToast(newest); }
  }, [edrAlerts]);
  useEffect(() => {
    if (!edrToast) return;
    const t = setTimeout(() => setEdrToast(null), 15_000);
    return () => clearTimeout(t);
  }, [edrToast]);
  const edrPivot = useMemo<EdrPivot>(() => ({
    canOpen: ev => !!ev.hostname && edrHosts.has(hostKey(ev.hostname)),
    open: ev => openEdr(asStr(ev.description) || "Endpoint alert", ev.hostname),
  }), [edrHosts, openEdr]);


  // The shift's load for the team currently in the lobby — the same numbers /start
  // will seed from (src/lib/team/load.ts), so the instructor sees them before starting.
  // The instructor's attack plan (staff only) fixes the concurrent attack count when set.
  const lobbyLoad = session && ["easy", "medium", "hard"].includes(session.difficulty)
    ? (session.attack_plan ? loadWithPlan(teamLoad(session.difficulty as Difficulty, roster), { ...session.attack_plan, bonus: session.attack_plan.bonus !== false }) : teamLoad(session.difficulty as Difficulty, roster)) : null;
  const chosenAttacks = session?.attack_plan?.slots.filter(Boolean).length ?? 0;

  // Native-format logs (docs/log-schemas), rendered for the session's company stack.
  // The 32 source modules load lazily once the shift is running.
  const [nativeMod, setNativeMod] = useState<typeof import("@/lib/logs/native") | null>(null);
  useEffect(() => {
    if (phase !== "running" || nativeMod) return;
    let alive = true;
    import("@/lib/logs/native").then(m => { if (alive) setNativeMod(m); }).catch(() => { /* legacy rendering stays */ });
    return () => { alive = false; };
  }, [phase, nativeMod]);
  const companyForNative = session?.company_id ?? "nexacorp";
  const stackForNative = (session as { stack?: Record<string, string> } | null)?.stack;
  const stackKey = JSON.stringify(stackForNative ?? {});
  // A named organization renders under its own domain / realm (FQDNs, UPNs, tenant names).
  const tenantDomain = session?.tenant?.domain, tenantRealm = session?.tenant?.netbios;
  const nativeRender = useMemo<NativeRenderer | null>(
    () => (nativeMod ? ev => nativeMod.nativeView(ev, companyForNative, JSON.parse(stackKey), tenantDomain && tenantRealm ? { domain: tenantDomain, netbios: tenantRealm } : undefined) : null),
    [nativeMod, companyForNative, stackKey, tenantDomain, tenantRealm],
  );

  if (loading) return <div className="flex items-center gap-2 p-6 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>;
  if (removed) return (
    <div className="p-6"><div className="flex items-start gap-2 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-4 py-3 text-sm text-neon-amber"><UserMinus className="mt-0.5 h-4 w-4 shrink-0" />
      <span>{removed} Anything you did before that still counts in the shift review. Ask your instructor if this was a mistake — they can add you back.</span></div>
      <Link href="/team" className="mt-3 inline-flex items-center gap-1 text-sm text-cyber-300"><ArrowLeft className="h-4 w-4" /> Back to team training</Link></div>
  );
  if (error && !session) return (
    <div className="p-6"><div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>
      <Link href="/team" className="mt-3 inline-flex items-center gap-1 text-sm text-cyber-300"><ArrowLeft className="h-4 w-4" /> Back</Link></div>
  );

  return (
    <IocTruthContext.Provider value={iocTruth}>
    <ItVerifyContext.Provider value={itVerify}>
    <EscalateCopyContext.Provider value={me?.role === "t2" || me?.role === "t3" ? OPEN_CASE_COPY : null}>
    <EdrPivotContext.Provider value={me?.role === "t1" || me?.role === "t2" || me?.role === "t3" ? edrPivot : null}>
    <NativeLogProvider value={nativeRender}>
    <div>
      <Topbar title={phase === "running" ? "Live team exercise" : phase === "ended" ? "Shift review" : "Team lobby"} subtitle={session ? `${session.tenant?.name ?? session.company_id} · ${session.difficulty}` : ""} />
      {/* Running: use the WHOLE screen width (a customer saw the centre column clipped
          with a sideways scroll on a laptop) — no max-width cap, slimmer side padding. */}
      <div className={`mx-auto ${phase === "running" ? "w-full max-w-none px-4 xl:px-6" : "container max-w-[1100px] px-6"} py-6 space-y-5`}>
        <Link href="/team" className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white"><ArrowLeft className="h-3.5 w-3.5" /> Team training</Link>
        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {note && phase !== "running" && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{note}</div>}
        {/* B8: EDR feedback shows in ANY phase (a pop-up-blocked click mid-shift must not be silent) */}
        {edrToast && phase === "running" && (me?.role === "t1" || me?.role === "t2" || me?.role === "t3") && (
          <div role="status" className="fixed bottom-20 right-4 z-50 w-[22rem] max-w-[calc(100vw-2rem)] rounded-lg border border-cyber-500/50 bg-bg-elevated px-4 py-3 shadow-2xl">
            <div className="flex items-start gap-2.5">
              <Cpu className="mt-0.5 h-4 w-4 shrink-0 text-cyber-300" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-wider text-cyber-300">New EDR alert</p>
                <p className="mt-0.5 text-sm text-slate-200"><bdi className="font-mono">{edrToast.host}</bdi></p>
                <p className="mt-0.5 line-clamp-2 text-[11px] text-slate-400">{edrToast.title}</p>
                <div className="mt-2 flex gap-2">
                  <Button size="sm" onClick={() => { openEdr(edrToast.title, edrToast.host); setEdrToast(null); }}>Investigate in EDR</Button>
                  <Button size="sm" variant="outline" onClick={() => setEdrToast(null)}>Later</Button>
                </div>
              </div>
              <button type="button" onClick={() => setEdrToast(null)} aria-label="Dismiss the EDR alert" className="rounded text-slate-400 hover:text-white"><X className="h-3.5 w-3.5" /></button>
            </div>
          </div>
        )}
        {edrNote && <div role="alert" className="fixed bottom-4 right-4 z-50 flex max-w-md items-center gap-2 rounded-lg border border-neon-amber/50 bg-bg-elevated px-4 py-3 text-sm text-neon-amber shadow-2xl"><AlertTriangle className="h-4 w-4 shrink-0" />{edrNote}<button onClick={() => setEdrNote(null)} aria-label="Dismiss" className="ml-auto rounded text-slate-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50"><X className="h-3.5 w-3.5" /></button></div>}

        {/* 3-2-1 countdown: one assertive announcement per number. The region stays
            mounted so the first number ("3") is announced too; the big visual is hidden from AT. */}
        <p className="sr-only" role="status" aria-live="assertive" aria-atomic="true">{countdown !== null ? `Exercise starts in ${countdown}` : ""}</p>
        {countdown !== null && (
          <div aria-hidden="true" className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
            <div className="text-center"><p className="text-sm uppercase tracking-[0.3em] text-cyber-300">Exercise starts in</p><p className="mt-2 font-mono text-8xl font-black text-white">{countdown}</p></div>
          </div>
        )}

        {showGuide && me && <RoleGuideModal role={me.role} onClose={() => setShowGuide(false)} />}

        {/* Who-just-left popups — every member sees them when a teammate drops. */}
        {leftNotices.length > 0 && (
          <div className="fixed right-4 top-20 z-50 flex w-72 flex-col gap-2">
            {leftNotices.map(n => (
              <div key={n.key} className="flex items-start gap-2 rounded-lg border border-neon-amber/40 bg-bg-elevated px-3 py-2 shadow-lg">
                <UserMinus className="mt-0.5 h-4 w-4 shrink-0 text-neon-amber" aria-hidden="true" />
                <p className="text-[12px] text-slate-200"><b><bdi>{n.name}</bdi></b> <span className="text-slate-400">({n.role})</span> left the session.</p>
                <button onClick={() => setLeftNotices(ns => ns.filter(x => x.key !== n.key))} aria-label="Dismiss notice" className="ml-auto shrink-0 rounded text-slate-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50"><X className="h-3.5 w-3.5" /></button>
              </div>
            ))}
          </div>
        )}

        {/* Training halted — a core role has nobody online. Blocks play until the
            team is back (auto-clears), or staff/Manager reassign / end. */}
        {haltActive && !haltDismissed && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 px-6">
            <div ref={haltRef} role="alertdialog" aria-modal="true" aria-labelledby="team-halt-title" aria-describedby="team-halt-msg" tabIndex={-1} className="max-w-md rounded-xl border border-neon-amber/40 bg-bg-elevated p-6 text-center shadow-2xl">
              <PauseCircle className="mx-auto h-10 w-10 text-neon-amber" aria-hidden="true" />
              <h3 id="team-halt-title" className="mt-3 text-lg font-bold text-white">Training paused</h3>
              <p id="team-halt-msg" className="mt-1 text-sm text-neon-amber">{haltMessage}</p>
              <p className="mt-2 text-[12px] text-slate-400">{pausedReason === "manual"
                ? "The instructor paused the shift. It stays paused until they resume it."
                : pausedReason === "owner_left"
                  ? `Nothing is lost — the shift resumes automatically when the instructor is back${canRunSession ? ", or you can resume / end it now." : "."}`
                  : `The shift can't run without the core team. It resumes automatically the moment they're back${canRunSession ? ", or you can reassign the role / end the session." : "."}`}</p>
              {canRunSession && (
                <div className="mt-4 flex flex-wrap justify-center gap-2">
                  <Button variant="outline" size="sm" onClick={() => setHaltDismissed(true)}>Manage (reassign)</Button>
                  {paused && <Button variant="outline" size="sm" disabled={busy} onClick={() => pauseSession(false)}>Resume now</Button>}
                  <Button variant="primary" size="sm" disabled={busy} onClick={end}><LogOut className="mr-1 h-3.5 w-3.5" /> End session</Button>
                </div>
              )}
            </div>
          </div>
        )}
        {haltActive && haltDismissed && (
          <div className="flex items-center gap-2 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-3 py-2 text-sm text-neon-amber">
            <PauseCircle className="h-4 w-4 shrink-0" /> Paused — {haltMessage} Reassign the seat below, or resume from the header.
          </div>
        )}

        {/* Work-division: coordinator's rebalance nudge — task-focused, no public
            call-out of the overloaded person (no-fault framing, U6); the Manager's
            Situation Board keeps the per-name detail. */}
        {phase === "running" && activeNudge && (() => {
          const p = activeNudge.payload as { target?: string; load?: number };
          const targetRole = roster.find(r => r.user_id === p.target)?.role;
          const queue = targetRole === "t1" ? "The Tier-1 alert queue" : targetRole === "t2" || targetRole === "t3" ? "The investigation queue" : "A teammate's queue";
          // T1-B playtest: the overloaded analyst got the same "if you're light…" line as
          // everyone else. They get a personal, actionable one (live load, else the nudge's).
          const mine = !!me && p.target === me.id;
          const myLoad = mine ? (openLoadByUser(events, nowTick).get(me!.id) ?? (typeof p.load === "number" ? p.load : 0)) : 0;
          return (
            <div role="status" className="flex items-center gap-2 rounded-lg border border-cyber-500/40 bg-cyber-500/[0.08] px-3 py-2 text-sm text-cyber-200">
              <Siren className="h-4 w-4 shrink-0 text-cyber-300" /> {mine
                ? <span><b>You&apos;re carrying {myLoad > 0 ? myLoad : "several"} open case{myLoad === 1 ? "" : "s"}</b> — <bdi>{nameOf(activeNudge.actor_id)}</bdi> asks you to hand one off or release a claim you&apos;re not actively working.</span>
                : <span><b>{queue}</b> is backing up — <bdi>{nameOf(activeNudge.actor_id)}</bdi> asks the team to rebalance. If you&apos;re light, take the next case.</span>}
              <button onClick={() => setDismissedNudgeSeq(activeNudge.seq ?? 0)} aria-label="Dismiss rebalance request" className="ml-auto shrink-0 rounded text-slate-400 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50"><X className="h-3.5 w-3.5" /></button>
            </div>
          );
        })()}

        {/* v2: coverage is decided server-side (heartbeats); show what this browser
            sees as a soft heads-up instead of blocking the room. */}
        {v2 && phase === "running" && !paused && haltReason && (
          <div role="status" className="flex items-center gap-2 rounded-lg border border-neon-amber/30 bg-neon-amber/[0.06] px-3 py-2 text-xs text-neon-amber">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" /> {haltReason} If they don&apos;t reconnect within a couple of minutes the shift pauses automatically — nothing is lost.
          </div>
        )}

        {/* ── LOBBY ── */}
        {phase === "lobby" && (
          <>
            {/* E-21 (QA phase 7): the lobby had no connection indicator — a dropped
                socket looked like "nobody else is ready". */}
            <div className="flex items-center gap-2 text-xs" aria-live="polite">
              {socketLive && !beatUnstable
                ? <span className="inline-flex items-center gap-1.5 text-neon-green"><Radio className="h-3.5 w-3.5" /> Connected to the lobby</span>
                : <span className="inline-flex items-center gap-1.5 text-neon-amber"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Reconnecting — ready states may be out of date</span>}
            </div>
            {/* Mission briefing — objectives + how you're scored, up front (no spoilers) */}
            <Card className="border-cyber-500/30">
              <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-cyber-300" /> Shift briefing</h2>
              <p className="mt-1 text-xs text-slate-400">A live SOC shift on a shared feed — expect a mix of noise and real activity. ~{lobbyLoad?.shiftMin ?? 30} min of live telemetry, then work the case to closure. Work as one team, tier to tier.</p>
              <p className="mt-1 text-[11px] text-slate-500"><span className="font-semibold text-slate-400">Security products:</span> {stackLine ? `${stackLine} — the rest are the company's own.` : "the company's own."}</p>
              {envLine && <p className="mt-0.5 text-[11px] text-slate-500"><span className="font-semibold text-slate-400">Environment:</span> {envLine}</p>}
              <div className="mt-2 grid gap-2 sm:grid-cols-3">
                {[["Keep the queue clean", "triage every alert — disposition it, don't let it pile up"],
                  ["Escalate with evidence", "hand off with a clear report + indicators, not a hunch"],
                  ["Contain the right asset", "scope it, get approval, isolate — no over-reaction"]].map(([t, d]) => (
                  <div key={t} className="rounded-lg border border-border bg-bg px-2.5 py-2">
                    <p className="text-[11px] font-semibold text-cyber-200">{t}</p>
                    <p className="mt-0.5 text-[10px] text-slate-500">{d}</p>
                  </div>
                ))}
              </div>
              <p className="mt-2 text-[10px] text-slate-500">Scored per role on a visible 0/4/8/12 rubric across the same three dimensions you&apos;re briefed on — <b className="text-slate-400">accuracy</b> · <b className="text-slate-400">timeliness</b> · <b className="text-slate-400">coordination</b>. No hidden scoring, and it&apos;s no-fault: catching and fixing your own mistake scores <b className="text-slate-400">for</b> you.</p>
            </Card>
            <Card>
              <div className="flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" /> Team roster</h2>
                <span className="font-mono text-xs text-slate-400">{players.filter(p => readyMap[p.user_id]).length}/{players.length} ready</span>
              </div>
              <div className="mt-3 space-y-1.5">
                {roster.filter(m => m.status !== "left").map(m => {
                  const isOn = online.has(m.user_id); const rdy = !!readyMap[m.user_id]; const isMe = me?.id === m.user_id;
                  return (
                    <div key={m.user_id} className={`flex items-center gap-3 rounded-lg border px-3 py-2 ${rdy ? "border-neon-green/30 bg-neon-green/[0.05]" : "border-border"}`}>
                      <span className={`h-2 w-2 shrink-0 rounded-full ${isOn ? "bg-neon-green" : "bg-slate-600"}`} title={isOn ? "connected" : "not connected"} aria-hidden="true" />
                      <span className="min-w-0 flex-1 truncate text-sm text-slate-200"><span className="sr-only">{isOn ? "Connected: " : "Not connected: "}</span><bdi>{m.name}</bdi>{isMe && <span className="ml-1 text-[11px] text-cyber-300">(you)</span>}
                        <span className="ml-2 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{ROLE_LABEL[m.role] ?? m.role}</span></span>
                      {m.role === "instructor" ? <span className="inline-flex items-center gap-1 text-[11px] text-neon-amber"><ShieldCheck className="h-3.5 w-3.5" /> runs it</span>
                        : rdy ? <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-neon-green"><CheckCircle2 className="h-3.5 w-3.5" /> ready</span>
                        : m.lapsed ? <span className="inline-flex items-center gap-1 text-[11px] text-severity-high" title="Their access to your organisation has expired — they can't mark ready."><AlertTriangle className="h-3.5 w-3.5" /> access expired</span>
                        : <span className="inline-flex items-center gap-1 text-[11px] text-slate-500"><Circle className="h-3.5 w-3.5" /> not ready</span>}
                      {me?.is_staff && m.role !== "instructor" && !isMe && <RemoveMemberButton sessionId={id} userId={m.user_id} name={m.name} onError={showError} />}
                    </div>
                  );
                })}
              </div>
            </Card>

            {/* Shift load, sized to this team (load.ts). Pace for everyone; the attack
                count only for staff — telling analysts how many attacks to find is a hint. */}
            {lobbyLoad && (
              <Card>
                <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Radio className="h-4 w-4 text-cyber-300" /> Shift pace</h2>
                <p className="mt-1 text-xs text-slate-400">
                  About <b className="text-slate-200">{lobbyLoad.logsPerMin} logs per minute</b> for {lobbyLoad.triageAnalysts === 1 ? "one Tier-1 analyst" : `${lobbyLoad.triageAnalysts} Tier-1 analysts`} over ~{lobbyLoad.shiftMin} minutes — the feed is sized so the Tier-1 team can read every log. Adding a Tier-1 analyst raises the pace; the whole team&apos;s size sets how much is going on.
                </p>
                {me?.is_staff && (
                  <p className="mt-2 rounded-lg border border-border bg-bg px-2.5 py-1.5 text-[11px] text-slate-400">
                    <span className="font-semibold text-slate-300">Staff only:</span> {lobbyLoad.players} player{lobbyLoad.players === 1 ? "" : "s"} → {lobbyLoad.stories} concurrent attack stor{lobbyLoad.stories === 1 ? "y" : "ies"}{session?.attack_plan?.count ? " (your choice)" : ""}{chosenAttacks ? ` — ${chosenAttacks} chosen, ${Math.max(0, lobbyLoad.stories - chosenAttacks)} random` : ""}{session?.attack_plan?.bonus !== false ? " (+1 bonus attack once all are caught)" : ""} + {lobbyLoad.poolAttacks} standalone attack{lobbyLoad.poolAttacks === 1 ? "" : "s"} on {session?.difficulty}. Final numbers are fixed when you start.
                  </p>
                )}
              </Card>
            )}

            {iAmPlayer && (
              <Card>
                <p className="text-sm text-slate-300">You&apos;re assigned <b className="text-white">{ROLE_LABEL[me!.role!] ?? me!.role}</b>. Marking ready confirms the rules of engagement (fight the problem, not the scenario · no-fault · your actions are measured for learning).</p>
                <div className="mt-3">
                  {iAmReady
                    ? <Button variant="outline" size="sm" disabled={busy} onClick={() => setReady(false)}>{busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <CheckCircle2 className="mr-1.5 h-4 w-4" />} I&apos;m ready — undo</Button>
                    : <Button variant="primary" size="sm" disabled={busy} onClick={() => setReady(true)}>{busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <CheckCircle2 className="mr-1.5 h-4 w-4" />} I&apos;m ready</Button>}
                </div>
              </Card>
            )}

            {me?.is_staff && (
              <Card className="border-cyber-500/30">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-bold text-white">Start the exercise</p>
                    <p className="text-xs text-slate-400">{allReady ? "All players are ready." : "Locked until every player marks ready — remove a no-show from the roster to start without them."}</p>
                    {lapsedPlayers.length > 0 && (
                      <p className="mt-1 flex items-center gap-1 text-xs text-severity-high"><AlertTriangle className="h-3.5 w-3.5" /> <bdi>{lapsedPlayers.map(p => p.name).join(", ")}</bdi> can&apos;t mark ready — access to your organisation has expired. Remove {lapsedPlayers.length === 1 ? "them" : "them all"} to start.</p>
                    )}
                    {!hasManager && (
                      <p className="mt-1 flex items-center gap-1 text-xs text-neon-amber"><AlertTriangle className="h-3.5 w-3.5" /> No SOC Manager or Lead on this team — CISO / Legal / exec requests will go unanswered. Add one below.</p>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                  <Button variant="primary" size="sm" disabled={busy || !allReady} onClick={start}>{busy ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Play className="mr-1.5 h-4 w-4" />} Confirm &amp; start</Button>
                  <Button variant="outline" size="sm" disabled={busy} onClick={end}>Close session</Button>
                </div>
                </div>
                {/* Grow the team before (or during) the shift — add a member to a role */}
                <AddMemberPanel sessionId={id} roster={roster} />
              </Card>
            )}
          </>
        )}

        {/* ── RUNNING ── */}
        {phase === "running" && me && (
          <>
            <div className="flex items-center gap-2 text-sm">
              {/* C6: real connection state, not a permanent "Live" */}
              {socketLive && pullHealthy
                ? <span className="inline-flex items-center gap-1.5 text-neon-green"><Radio className="h-4 w-4 animate-pulse" /> Live — same feed for the whole team</span>
                : socketLive
                  ? <span className="inline-flex items-center gap-1.5 text-neon-amber" title="Realtime is up but the catch-up sync is failing — some logs may arrive late."><AlertTriangle className="h-4 w-4" /> Degraded — syncing</span>
                  : <span className="inline-flex items-center gap-1.5 text-neon-amber" title="Reconnecting to the live room — missed logs are fetched automatically."><Loader2 className="h-4 w-4 animate-spin" /> Reconnecting…</span>}
              {beatUnstable && (
                <span className="inline-flex items-center gap-1 rounded border border-neon-amber/40 bg-neon-amber/10 px-1.5 py-0.5 text-[11px] text-neon-amber" title="Your presence pings aren't reaching the server. If this lasts ~2 minutes the shift may pause for coverage.">
                  <AlertTriangle className="h-3 w-3" /> Connection unstable
                </span>
              )}
              <span className="ml-auto font-mono text-xs text-slate-500">{online.size} online · {feed.length} logs · you: {ROLE_LABEL[me.role ?? ""] ?? "observer"}</span>
              <Button variant="outline" size="sm" onClick={() => setShowGuide(true)}>? Guide</Button>
              {canRunSession && (paused
                ? <Button variant="outline" size="sm" disabled={busy} onClick={() => pauseSession(false)}>Resume</Button>
                : <Button variant="outline" size="sm" disabled={busy} onClick={() => pauseSession(true)}><PauseCircle className="mr-1 h-3.5 w-3.5" /> Pause</Button>)}
              {canRunSession && <Button variant="outline" size="sm" disabled={busy} onClick={end}>End session</Button>}
            </div>

            {/* Always-visible "what do I do now" directive for the player's role */}
            <div className="flex items-start gap-2 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-3 py-2 text-sm">
              <span className="shrink-0 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase text-cyber-300">{ROLE_LABEL[me.role ?? ""] ?? "observer"}</span>
              <span className="text-slate-200">{roleDirective(me.role)}</span>
              <button onClick={() => setShowGuide(true)} className="ml-auto shrink-0 rounded text-[11px] text-cyber-300 underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyber-400/50">how my role works →</button>
            </div>

            {/* Silent-failure nudge (F6): attack active, nobody escalated yet */}
            {guidingNudge && me.role !== "instructor" && me.role !== "observer" && (
              <div role="status" className="flex items-start gap-2 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-3 py-2 text-sm">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-neon-amber" />
                <span className="text-neon-amber"><b>Heads up —</b> {guidingNudge}</span>
              </div>
            )}

            {/* Shared case — the team's single shared truth; collapsible summary bar (G-02) */}
            <SharedCase events={events} feed={feed} roster={roster} me={me} act={act} nameOf={nameOf} />

            {/* Running layout: wide page, and Tier-2/3 — whose work is reading escalated
                logs and writing reports in the role column — get an even split instead
                of a narrow side rail. The left column is sticky so the feed and the team
                chat stay in view while the role column scrolls (no empty half-page). */}
            <div className={`grid gap-4 ${me.role === "t2" || me.role === "t3" ? "lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]" : "lg:grid-cols-[minmax(0,1fr)_minmax(360px,32%)]"}`}>
              {/* Left column: raw feed for analysts; a summaries-only Situation Board
                  for the coordinator SEAT (Lead/Mgr) — §3.7 keeps coordinators OUT of
                  raw (G-08). Decided by the seat, not org rights (U9): a Manager who
                  also has instructor rights still commands from summaries. The
                  instructor seat (role "instructor") keeps the raw feed for oversight. */}
              {/* overflow-x-hidden: overflow-y:auto alone silently turns X into a scroll
                  container too, which is how the feed ended up clipped + sideways-scrolled. */}
              <div className="min-w-0 space-y-3 lg:sticky lg:top-20 lg:max-h-[calc(100vh-6rem)] lg:self-start lg:overflow-y-auto lg:overflow-x-hidden lg:pr-1">
                {(me.role === "lead" || me.role === "mgr") ? (
                  <SituationBoard liveFeed={liveFeed} events={events} feed={feed} nameOf={nameOf} roster={roster} online={online} act={act} />
                ) : (
                  <>
                    {/* Scenario review fix 6: a help-desk ticket is Tier-1's to answer — say so where Tier-1 looks. */}
                    {me.role === "t1" && openTickets > 0 && (
                      <button type="button" onClick={() => document.getElementById("team-injects")?.scrollIntoView({ behavior: "smooth", block: "start" })}
                        className="flex w-full items-center gap-2 rounded-lg border border-neon-amber/50 bg-neon-amber/10 px-3 py-2 text-left text-sm font-semibold text-neon-amber transition hover:bg-neon-amber/15">
                        <span aria-hidden>📞</span>
                        <span className="flex-1">{openTickets === 1 ? "A help-desk ticket is waiting for you" : `${openTickets} help-desk tickets are waiting for you`} — Tier-1 answers these.</span>
                        <span className="text-xs underline">Answer now</span>
                      </button>
                    )}
                    {/* Tier-1: the alert queue is a view of this SIEM, not a separate panel */}
                    {me.role === "t1" && (
                      <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-elevated/40 px-2 py-1.5">
                        <div role="tablist" aria-label="SIEM view" className="flex gap-1">
                          <button role="tab" aria-selected={feedView === "all"} onClick={() => setFeedView("all")}
                            className={`rounded px-2.5 py-1 text-[11px] font-semibold transition ${feedView === "all" ? "border border-cyber-500/40 bg-cyber-500/15 text-cyber-300" : "border border-transparent text-slate-400 hover:text-slate-200"}`}>
                            All events
                          </button>
                          <button role="tab" aria-selected={feedView === "triage"} onClick={() => setFeedView("triage")}
                            className={`flex items-center gap-1.5 rounded px-2.5 py-1 text-[11px] font-semibold transition ${feedView === "triage" ? "border border-cyber-500/40 bg-cyber-500/15 text-cyber-300" : "border border-transparent text-slate-400 hover:text-slate-200"}`}>
                            Needs triage
                            <span className={`rounded-full px-1.5 font-mono text-[10px] ${alertQueue.some(q => q.orphan) ? "bg-severity-high/20 text-severity-high" : "bg-slate-700/60 text-slate-200"}`}>{alertQueue.length}</span>
                          </button>
                        </div>
                        <label className="flex items-center gap-1 text-[10px] text-slate-400" title="Early signs of an attack often arrive as medium — include them in Needs triage">
                          <input type="checkbox" checked={queueWithMedium} onChange={e => setQueueWithMedium(e.target.checked)} className="h-3 w-3" /> include medium
                        </label>
                        {pulledNote && <span role="status" className="text-[11px] text-neon-green">{pulledNote}</span>}
                        <Button variant="outline" size="sm" className="ml-auto" disabled={alertQueue.length === 0} onClick={takeNextAlert}>Take next alert</Button>
                      </div>
                    )}
                    {/* Endpoint alerts → EDR, for the analysts (muted until an EDR alert arrives). */}
                    {(me.role === "t1" || me.role === "t2" || me.role === "t3") && (() => {
                      const last = edrAlerts[edrAlerts.length - 1];
                      return (
                        <div className="flex items-center gap-2">
                          <button type="button" disabled={!last} onClick={() => last && openEdr(last.title, last.host)}
                            title={last ? `Latest EDR alert: ${last.title} (${last.host})` : "No endpoint alerts yet: this lights up when an EDR alert reaches the feed"}
                            className={`relative flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-semibold transition ${last ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-200 hover:bg-cyber-500/20" : "cursor-not-allowed border-border bg-bg text-slate-500"}`}>
                            <Cpu className="h-3.5 w-3.5" aria-hidden /> Investigate in EDR
                            {edrAlerts.length > 0 && (
                              <span className="absolute -right-2 -top-2 flex h-5 min-w-[1.25rem] animate-pulse items-center justify-center rounded-full bg-severity-critical px-1 text-[10px] font-bold text-white shadow ring-2 ring-bg-elevated">
                                {edrAlerts.length}<span className="sr-only"> endpoint alert{edrAlerts.length > 1 ? "s" : ""}</span>
                              </span>
                            )}
                          </button>
                          {last && <span className="min-w-0 truncate text-[11px] text-slate-400">Latest: <bdi className="font-mono text-slate-300">{last.host}</bdi></span>}
                        </div>
                      );
                    })()}
                    {/* G-04: surfaced feed filters + active click-to-pivot chips */}
                    <FeedFilterBar
                      severity={fSeverity} setSeverity={setFSeverity}
                      source={fSource} setSource={setFSource} sources={feedSources}
                      search={fSearch} setSearch={setFSearch}
                      pivots={[["user", fUser, setFUser], ["host", fHost, setFHost], ["ip", fIp, setFIp]]}
                    />
                    <EventFeed
                      events={me.role === "t1" && feedView === "triage" ? triageFeed : liveFeed}
                      emptyMessage={me.role === "t1" && feedView === "triage" ? `Nothing needs triage — every ${queueWithMedium ? "medium+" : "high/critical"} alert has a disposition. Keep watching All events.` : "Waiting for the first logs…"}
                      severityFilter={fSeverity} sourceFilter={fSource} search={fSearch}
                      userFilter={fUser} hostFilter={fHost} ipFilter={fIp}
                      // I5: only the CLOSE carries the dwell the AAR uses — the open event was pure overhead.
                      onRowOpened={onFeedRowOpened}
                      onPivot={onFeedPivot}
                      onAddIoc={me.role === "t1" ? onFeedAddIoc : undefined}
                      rowStatus={rowStatus}
                      onEscalate={me.role === "t1" ? onFeedEscalate : me.role === "t2" || me.role === "t3" ? onFeedOpenCase : undefined}
                    />
                  </>
                )}
              </div>
              {/* YOUR ROLE — the dominant role panel(s), then secondary panels tabbed (G-03) */}
              <div className="min-w-0 space-y-4">
                {me.role === "t1" && <T1Console sessionId={id} feed={feed} dispositions={dispositions} events={events} meId={me.id} iocDraft={iocDraft} setIocDraft={setIocDraft} nameOf={nameOf} act={act} actR={actR} sel={t1Sel} setSel={setT1Sel} reportOpen={t1ReportOpen} setReportOpen={setT1ReportOpen} />}
                {/* B12: Tier-3's dominant surface is HUNTING — render it above the (secondary) inbox. */}
                {me.role === "t3" && <HuntConsole canEdr={canEdr} scope={scopeState} scopes={scopes} incidents={incidents} incidentOf={incidentOf} elevations={elevations} elevAcked={elevAcked} nameOf={nameOf} act={act} onEdr={openEdr} onPivot={onFeedPivot} />}
                {(me.role === "t2" || me.role === "t3") && <T2Console canEdr={canEdr} sessionId={id} role={me.role} meId={me.id} escalations={escalations} escState={escStates} reportedIds={reportedIds} reportByEid={reportByEid} elevatedIds={elevatedIds} containments={containments} scope={scopeState} scopes={scopes} incidents={incidents} incidentOf={incidentOf} nameOf={nameOf} act={act} actR={actR} onEdr={openEdr} onPivot={onFeedPivot} pauses={pauseSpans} />}
                {/* SOC Manager now holds the coordinator authority (approve containment,
                    decision log, SITREP) as well as shift management. 'lead'/'de' branches
                    stay for backward-compatibility with older sessions; 'ti' is a live seat. */}
                {(me.role === "lead" || me.role === "mgr") && <LeadConsole events={events} nameOf={nameOf} act={act} />}
                {me.role === "de" && <DEConsole liveFeed={liveFeed} events={events} act={act} />}
                {me.role === "ti" && <TIConsole events={events} feed={feed} nameOf={nameOf} act={act} />}
                {me.role === "mgr" && <MgrConsole roster={roster} events={events} act={act} />}
                {/* QA L4: another instructor of the org (staff, no seat in this session) gets the panel too — every
                    staff tool except the inject composer, which posts as the session's instructor seat. */}
                {(me.role === "instructor" || (me.is_staff && !me.role)) && <InstructorPanel sessionId={id} roster={roster} online={online} events={events} act={act} isStaff={!!me.is_staff} nameOf={nameOf} canInject={me.role === "instructor"} onError={showError} />}
                {/* The team chat sits with the role panels, never under the feed: a chat under the
                    log list covered the log being read (Tal, 2026-10-08). It folds to one line. */}
                <WarRoom sessionId={id} events={events} me={me} nameOf={nameOf} act={act} />
                {/* Team intel — its own visible card (was buried in a folded tab) */}
                <TeamIntel events={events} nameOf={nameOf} />
                {/* G-14: injects / announcements / help-desk tickets — visible to everyone */}
                <InjectFeed sessionId={id} events={events} me={me} nameOf={nameOf} act={act} hasManager={hasManager} />
                {/* The team's action log, folded so the role panel stays dominant (chat moved out, left column) */}
                <SecondaryPanels activity={activity} nameOf={nameOf} />
              </div>
            </div>
          </>
        )}

        {phase === "ended" && me && (
          <>
            {endReason === "owner_left" && <div className="flex items-center gap-2 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-4 py-3 text-sm text-neon-amber"><LogOut className="h-4 w-4 shrink-0" /> The session owner (instructor) left the live room, so the session was closed automatically.</div>}
            <TeamReport sessionId={id} events={events} roster={roster} me={me} />
          </>
        )}
      </div>
    </div>
      {caseLog && (me?.role === "t2" || me?.role === "t3") && (
        <OpenCaseModal log={caseLog} role={me.role} onClose={() => setCaseLog(null)} act={act} actR={actR} />
      )}
    </NativeLogProvider>
    </EdrPivotContext.Provider>
    </EscalateCopyContext.Provider>
    </ItVerifyContext.Provider>
    </IocTruthContext.Provider>
  );
}

