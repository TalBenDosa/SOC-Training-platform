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
import { EventFeed, DetailPanelBody } from "@/app/(app)/dashboard/EventFeed";
import { ThreatIntelDrawer, type ThreatQuery } from "@/components/threat-intel/ThreatIntelDrawer";
import { enrichEvent, type LiveEvent } from "@/app/(app)/dashboard/useLiveEvents";
import { eventMatchesSearch } from "@/app/(app)/dashboard/eventSearch";
import type { TelemetryEvent } from "@/lib/sim/types";
import { buildInvestigationFromStory } from "@/lib/edr/fromLiveStory";
import {
  Loader2, AlertTriangle, CheckCircle2, Circle, Radio, Play, ShieldCheck, ArrowLeft, Users,
  ArrowUpRight, Check, ShieldAlert, Siren, FolderOpen, Filter, X, ChevronDown, Search, Clock, FileText,
  UserPlus, UserMinus, PauseCircle, LogOut,
} from "lucide-react";

interface RosterMember { user_id: string; role: string; status: string; name: string; handle: string | null }
interface SessionMeta { id: string; company_id: string; difficulty: string; status: string; org_id: string }
interface Me { id: string; is_staff: boolean; role: string | null }
interface Ev { seq: number; type: string; actor_id: string | null; role: string | null; payload: Record<string, unknown>; occurred_at?: string }

const ROLE_LABEL: Record<string, string> = {
  t1: "Tier-1 Triage", t2: "Tier-2 Investigator", t3: "Tier-3 / Threat Hunter",
  lead: "Incident Lead", de: "Detection Engineer", ti: "Threat Intel", mgr: "SOC Manager",
  instructor: "Instructor", observer: "Observer",
};
const IMPACTS = ["host", "user", "segment", "org"];

// How a real SOC ticket flows tier-to-tier (grounded in the SOC operations
// research + docs/SPEC-team-roles-playbook.md). Shown in the first-use guide.
const OVERALL_FLOW = "A real incident moves tier to tier, investigated deeper at each hop: Tier-1 triages the alert queue and escalates the real ones with evidence → Tier-2 acknowledges, investigates in depth and asks for containment → Tier-3 hunts deeper and confirms scope → the SOC Manager approves containment, records decisions & SITREPs, and drives the case to closure. Everyone works one Shared Case.";
interface RoleGuide { mission: string; steps: string[]; flow: string; measured: string[] }
const ROLE_GUIDE: Record<string, RoleGuide> = {
  t1: { mission: "You're the front line — triage every alert fast and pass the real ones up with evidence.",
    steps: ["Watch the Live SIEM feed; click a log to read its raw detail.", "Set a disposition on each in your console: True Positive / False Positive / Benign.", "For anything real, fill the Escalate-to-Tier-2 form (what you saw · why it's suspicious · impact · confidence) and send it.", "📌 Pin the key logs to the Shared Case."],
    flow: "IN: raw alerts from the feed.  OUT: escalate to Tier-2 (escalation.requested).", measured: ["Disposition accuracy vs ground truth", "Escalation completeness & correctness", "Time to triage"] },
  t2: { mission: "You take Tier-1's escalations and run them to ground.",
    steps: ["Open 'Escalations for you' and Acknowledge each (so T1 knows it's owned).", "Investigate: pivot in the feed, open the EDR console, build the timeline, pin evidence.", "Set the case scope; keep the Shared Case status current.", "When containment is needed, send a Containment request to the SOC Manager."],
    flow: "IN: escalation.requested from T1.  OUT: containment.requested to the SOC Manager; loop in T3 for deep hunts.", measured: ["Acknowledge latency", "Scope accuracy", "Quality & timing of the containment request"] },
  t3: { mission: "Senior investigator & threat hunter — go deeper than the queue.",
    steps: ["Take the hardest escalations from the inbox.", "Form a hypothesis and hunt the feed for related activity.", "Log your hunt findings (hypothesis → evidence → MITRE technique).", "Confirm the real scope and advise Tier-2."],
    flow: "IN: hard cases from T2.  OUT: findings & confirmed scope to the SOC Manager, guidance to T2.", measured: ["Hunt findings yield", "Scope / attribution accuracy", "Depth of investigation"] },
  lead: { mission: "Incident Commander — coordinate, decide, own the case. You don't investigate yourself.",
    steps: ["Watch the Shared Case and the team's requests.", "Approve or deny Containment requests (with a reason).", "Advance the case status and assign the owner.", "Drive the case toward Contained → Closed."],
    flow: "IN: containment.requested from T2/T3.  OUT: approve/deny + case decisions.", measured: ["Decision speed & correctness", "Case progression", "Coordination"] },
  de: { mission: "Detection Engineer — close detection gaps live.",
    steps: ["Follow what the team is chasing.", "Write a rule (name + keyword) — it back-tests against the live feed instantly.", "Publish rules that catch the attack technique.", "Tune to cut noise."],
    flow: "You support the whole team by turning findings into detections (rule.published).", measured: ["Rule matches (verifiable)", "False-positive rate", "Time to publish"] },
  ti: { mission: "Threat Intel — turn indicators into context and prediction.",
    steps: ["Follow the incident's indicators.", "Publish an intel note: actor/technique · confidence · recommended action · next expected step.", "Tell the team what to block and what's coming."],
    flow: "You support T1/T2/Lead with actionable intel (intel.published → Team intel card).", measured: ["Actionable notes", "Attribution accuracy", "Predicting the next step"] },
  mgr: { mission: "SOC Manager — the incident authority: approve containment, coordinate, and keep the shift healthy.",
    steps: ["Approve or deny containment requests from Tier-2 (weigh the business impact).", "Log key decisions and send a SITREP as the picture develops.", "Watch workload/SLA; at shift end, sign the passdown (open cases · next steps)."],
    flow: "You approve containment (containment.approved), record decisions & SITREPs, and own the shift handover.", measured: ["Time-to-approval", "Workload balance", "SITREP cadence", "Handover quality"] },
  instructor: { mission: "You run the exercise — monitor every role, then end it to reveal the report.",
    steps: ["Watch the roster and Team activity.", "Let the incident unfold; the feed streams to everyone live.", "Click 'End exercise' to generate the after-action report."],
    flow: "You control the session; the players work their roles.", measured: ["—"] },
};
function roleDirective(role: string | null | undefined): string {
  switch (role) {
    case "t1": return "Triage the feed — set a disposition on each log, and escalate anything real to Tier-2.";
    case "t2": return "Work your escalation inbox — acknowledge, investigate, then request containment from the SOC Manager.";
    case "t3": return "Hunt deeper — take hard cases, log findings, confirm scope.";
    case "lead": return "Command the incident — approve/deny containment and drive the case status.";
    case "de": return "Write & publish detection rules that catch the attack (they back-test live).";
    case "ti": return "Publish intel — actor, technique, and the next expected step.";
    case "mgr": return "Approve/deny containment, log decisions & SITREPs, balance the shift, and sign the passdown.";
    case "instructor": return "Monitor all roles; end the exercise to reveal the report.";
    default: return "Watch the shared feed.";
  }
}
function RoleGuideModal({ role, onClose }: { role: string | null; onClose: () => void }) {
  const g = ROLE_GUIDE[role ?? ""] ?? ROLE_GUIDE.instructor;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={onClose}>
      <div className="max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-bg-elevated p-5" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white">Your role: {ROLE_LABEL[role ?? ""] ?? "Observer"}</h2>
          <button onClick={onClose} aria-label="Close" className="text-xl leading-none text-slate-400 hover:text-white">&times;</button>
        </div>
        <p className="mt-2 text-sm text-slate-200">{g.mission}</p>
        <div className="mt-4">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">What you do</p>
          <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-slate-300">{g.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
        </div>
        <div className="mt-3 rounded-lg border border-border bg-bg px-3 py-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Hand-off</p>
          <p className="mt-0.5 text-xs text-slate-300">{g.flow}</p>
        </div>
        <div className="mt-3">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">You&apos;re measured on</p>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-xs text-slate-400">{g.measured.map((m, i) => <li key={i}>{m}</li>)}</ul>
        </div>
        <div className="mt-4 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-3 py-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-cyber-300">How the team works together</p>
          <p className="mt-0.5 text-xs text-slate-300">{OVERALL_FLOW}</p>
        </div>
        <Button variant="primary" size="sm" className="mt-4 w-full" onClick={onClose}>Got it</Button>
      </div>
    </div>
  );
}

export default function TeamRoomPage() {
  const { id } = useParams<{ id: string }>();
  usePageTitle("Team session");

  const [session, setSession] = useState<SessionMeta | null>(null);
  const [roster, setRoster] = useState<RosterMember[]>([]);
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const [online, setOnline] = useState<Set<string>>(new Set());
  const [readyMap, setReadyMap] = useState<Record<string, boolean>>({});
  const [phase, setPhase] = useState<"lobby" | "running" | "ended">("lobby");
  const [countdown, setCountdown] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  // event log (ALL types), deduped by seq
  const [events, setEvents] = useState<Ev[]>([]);
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
  const [t1ReportOpen, setT1ReportOpen] = useState(false);
  const seqSeen = useRef<Set<number>>(new Set());
  const maxSeqRef = useRef(0);
  const channelRef = useRef<RealtimeChannel | null>(null);

  const nameOf = useCallback((uid: string | null) => uid ? (roster.find(r => r.user_id === uid)?.name ?? uid.slice(0, 8)) : "system", [roster]);

  const mergeEvents = useCallback((incoming: Ev[]) => {
    const fresh = incoming.filter(e => typeof e.seq === "number" && !seqSeen.current.has(e.seq));
    if (fresh.length === 0) return;
    fresh.forEach(e => { seqSeen.current.add(e.seq); if (e.seq > maxSeqRef.current) maxSeqRef.current = e.seq; });
    setEvents(prev => [...prev, ...fresh].sort((a, b) => a.seq - b.seq));
  }, []);

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
      const res = await fetch(`/api/team/sessions/${id}`);
      if (!res.ok) { if (!cancelled) { setError((await res.json().catch(() => ({})))?.error ?? "Failed to load."); setLoading(false); } return; }
      const data = await res.json();
      if (cancelled) return;
      setSession(data.session); setRoster(data.roster); setMe(data.me);
      setReadyMap(Object.fromEntries((data.roster as RosterMember[]).map(m => [m.user_id, m.status === "ready" || m.status === "active"])));
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

  // ── running/ended: initial event load + DB reconcile safety-net (so nobody
  //    misses a log, and the report has the full event history) ──
  useEffect(() => {
    if (phase !== "running" && phase !== "ended") return;
    const sb = getSupabaseBrowserClient();
    if (!sb) return;
    let stop = false;
    const pull = async () => {
      // Paginate by seq cursor in 1000-row pages (PostgREST caps a single query at
      // ~1000 rows) so a long session's newest events — incl. escalations — always load.
      let cursor = maxSeqRef.current;
      for (let guard = 0; guard < 30 && !stop; guard++) {
        const { data } = await sb.from("session_events").select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", id).gt("seq", cursor).order("seq").limit(1000);
        if (stop || !data || data.length === 0) break;
        mergeEvents(data as Ev[]);
        cursor = (data[data.length - 1] as Ev).seq;
        if (data.length < 1000) break;
      }
    };
    pull();
    // Realtime broadcast is the primary delivery. Reconcile from the DB only when
    // the channel is unhealthy OR has been silent for a while (a possibly-missed
    // broadcast) — so a healthy, active session costs ~no steady-state DB polling.
    const iv = phase === "running" ? setInterval(() => {
      if (!channelHealthyRef.current || Date.now() - lastRealtimeAtRef.current > 25000) pull();
    }, 10000) : null;
    return () => { stop = true; if (iv) clearInterval(iv); };
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
          setReadyMap(prev => { const n = { ...prev }; for (const [uid, m] of Object.entries(state)) { const r = m[0]?.ready; if (typeof r === "boolean") n[uid] = r; } return n; });
        })
        .on("broadcast", { event: "session_event" }, ({ payload }) => {
          lastRealtimeAtRef.current = Date.now(); // realtime is alive → the reconcile pull can stay idle
          const p = payload as Ev & { actor_id?: string };
          if (p.type === "member.ready" && p.actor_id) setReadyMap(m => ({ ...m, [p.actor_id!]: true }));
          else if (p.type === "member.unready" && p.actor_id) setReadyMap(m => ({ ...m, [p.actor_id!]: false }));
          else if (p.type === "session.started") { setSession(s => s ? { ...s, status: "running" } : s); startCountdown(); }
          else if (p.type === "session.ended") { setSession(s => s ? { ...s, status: "ended" } : s); setCountdown(null); setPhase("ended"); const rr = (p.payload as { reason?: string })?.reason; if (rr) setEndReason(rr); }
          else if (p.type === "session.paused") { setSession(s => s ? { ...s, status: "paused" } : s); setPaused(true); const pl = p.payload as { reason?: string; detail?: string }; setPausedReason(pl?.reason ?? "manual"); setPausedDetail(pl?.detail ?? null); }
          else if (p.type === "session.resumed") { setSession(s => s ? { ...s, status: "running" } : s); setPaused(false); setPausedReason(null); setPausedDetail(null); }
          if (typeof p.seq === "number") mergeEvents([{ seq: p.seq, type: p.type, actor_id: p.actor_id ?? null, role: p.role ?? null, payload: p.payload ?? {}, occurred_at: (p as { occurred_at?: string }).occurred_at }]);
        })
        .subscribe(async status => {
          channelHealthyRef.current = status === "SUBSCRIBED";
          if (status === "SUBSCRIBED") { lastRealtimeAtRef.current = Date.now(); await channel.track({ ready: !!(me && roster.find(r => r.user_id === me.id)?.status === "ready") }); }
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
  const act = useCallback(async (type: string, payload: Record<string, unknown>) => {
    const sb = getSupabaseBrowserClient();
    if (!sb) return false;
    const { error: e } = await sb.rpc("apply_session_action", { p_session: id, p_type: type, p_payload: payload, p_idempotency_key: `${type}-${me?.id}-${Date.now()}` });
    if (e) { setError(e.message); return false; }
    return true;
  }, [id, me?.id]);

  async function setReady(ready: boolean) {
    setBusy(true); setError(null);
    const ok = await act(ready ? "member.ready" : "member.unready", {});
    setBusy(false);
    if (ok) { setReadyMap(m => ({ ...m, [me!.id]: ready })); await channelRef.current?.track({ ready }); }
  }
  async function start() {
    setBusy(true); setError(null);
    const res = await fetch(`/api/team/sessions/${id}/start`, { method: "POST" });
    setBusy(false);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) { setError(data?.error ?? "Could not start."); return; }
    setNote("Exercise starting…"); startCountdown();
  }
  async function end() {
    if (!confirm("End the exercise for the whole team and show the after-action report?")) return;
    setBusy(true); setError(null);
    const res = await fetch(`/api/team/sessions/${id}/end`, { method: "POST" });
    setBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not end."); return; }
    setPhase("ended");
  }
  async function pauseSession(p: boolean) {
    setBusy(true); setError(null);
    const res = await fetch(`/api/team/sessions/${id}/pause`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused: p, reason: "manual" }) });
    setBusy(false);
    if (!res.ok) { setError((await res.json().catch(() => ({})))?.error ?? "Could not update the session."); return; }
    setPaused(p); setPausedReason(p ? "manual" : null); setPausedDetail(null); // optimistic; broadcast confirms for all
  }

  // ── derived ─────────────────────────────────────────────────────────────────
  // Observers watch only — they never "ready up", so they must not count toward the
  // ready-check (otherwise an observer wedges Start forever) nor the coverage set.
  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");
  const allReady = players.length > 0 && players.every(p => readyMap[p.user_id]);
  const iAmPlayer = !!(me && me.role && me.role !== "instructor" && me.role !== "observer");
  const iAmReady = !!(me && readyMap[me.id]);
  const canRunSession = !!(me && (me.is_staff || me.role === "mgr")); // who may end/manage

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
  const haltActive = phase === "running" && (paused || haltConfirmed);
  const haltMessage = paused
    ? (pausedReason === "manual" ? "Paused by the instructor." : (pausedDetail || "Not enough of the team is online right now."))
    : (haltReason ?? "");
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
    if (phase !== "running" || !me || !presenceReady || autoPauseBusyRef.current) return;
    const elected = roster.filter(r => online.has(r.user_id)).map(r => r.user_id).sort()[0];
    if (elected !== me.id) return;
    const call = async (p: boolean, detail?: string) => {
      autoPauseBusyRef.current = true;
      try { await fetch(`/api/team/sessions/${id}/pause`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ paused: p, reason: "coverage", detail }) }); }
      catch { /* transient — the next presence sync retries */ }
      finally { autoPauseBusyRef.current = false; }
    };
    if (haltConfirmed && !paused) call(true, haltReason || undefined);
    else if (!haltReason && paused && pausedReason === "coverage") call(false);
  }, [phase, me, presenceReady, roster, online, haltReason, haltConfirmed, paused, pausedReason, id]);

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

  // Owner (instructor) left the live room → auto-close after a short grace, so a
  // brief refresh doesn't kill the session. One elected online client fires it.
  useEffect(() => {
    if (phase !== "running" || !instructor || !me) {
      if (ownerGoneTimer.current) { clearTimeout(ownerGoneTimer.current); ownerGoneTimer.current = null; }
      return;
    }
    if (online.has(instructor.user_id)) { // owner present — cancel any pending close
      if (ownerGoneTimer.current) { clearTimeout(ownerGoneTimer.current); ownerGoneTimer.current = null; }
      return;
    }
    if (ownerGoneTimer.current || autoEndFiredRef.current) return;
    ownerGoneTimer.current = setTimeout(async () => {
      ownerGoneTimer.current = null;
      if (autoEndFiredRef.current || online.has(instructor.user_id)) return;
      // elect the lowest online player id so exactly one client closes the session.
      const elected = roster.filter(r => r.role !== "instructor" && online.has(r.user_id)).map(r => r.user_id).sort()[0];
      if (!elected || elected !== me.id) return;
      autoEndFiredRef.current = true;
      await fetch(`/api/team/sessions/${id}/end`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason: "owner_left" }) }).catch(() => {});
    }, 30000);
    return () => { if (ownerGoneTimer.current) { clearTimeout(ownerGoneTimer.current); ownerGoneTimer.current = null; } };
    // onlineSig (not the online Set) keeps the 30s timer from resetting on every
    // presence heartbeat — it re-runs only when membership actually changes (C8).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, instructor, onlineSig, me, roster, id]);

  const feed = useMemo(() => events.filter(e => e.type === "feed.event"), [events]);
  const escalations = useMemo(() => events.filter(e => e.type === "escalation.requested"), [events]);
  const acked = useMemo(() => new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String(e.payload.event_id))), [events]);
  // G-07 escalation state machine.
  const escBounced = useMemo(() => new Set(events.filter(e => e.type === "escalation.bounced").map(e => String(e.payload.event_id))), [events]);
  const escResolved = useMemo(() => new Set(events.filter(e => e.type === "escalation.resolved").map(e => String(e.payload.event_id))), [events]);
  // Routed escalations: who first acknowledged (= claimed) each escalation, so a
  // second Tier-2 sees it's already being worked and doesn't double-handle it.
  const ackedBy = useMemo(() => {
    const m = new Map<string, string>();
    for (const e of events) if (e.type === "escalation.acknowledged") { const id = String(e.payload.event_id); if (!m.has(id)) m.set(id, e.actor_id ?? ""); }
    return m;
  }, [events]);
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
  // Silent-failure guard (F6): if attack activity has been streaming for a while and
  // NOBODY has escalated yet, surface a team-level nudge so a missed attack doesn't
  // pass in silence until the debrief. Clears the moment anyone escalates.
  const guidingNudgeMins = useMemo(() => {
    if (events.some(e => e.type === "escalation.requested")) return null;
    const firstAttack = feed.find(e => { const v = (e.payload as { expected_verdict?: string }).expected_verdict; return v === "tp" || v === "escalate"; });
    if (!firstAttack?.occurred_at) return null;
    const mins = Math.floor((Date.now() - Date.parse(firstAttack.occurred_at)) / 60000);
    return mins >= 3 ? mins : null;
  }, [feed, events]);
  const contReq = useMemo(() => events.filter(e => e.type === "containment.requested"), [events]);
  const contDecided = useMemo(() => new Set(events.filter(e => e.type === "containment.approved" || e.type === "containment.denied").map(e => String(e.payload.event_id))), [events]);
  // G-09: approved-but-not-yet-executed containments, and the set already executed.
  const contApproved = useMemo(() => new Set(events.filter(e => e.type === "containment.approved").map(e => String(e.payload.event_id))), [events]);
  const contExecuted = useMemo(() => new Set(events.filter(e => e.type === "containment.executed").map(e => String(e.payload.event_id))), [events]);
  // G-10: latest working scope (T2 sets, T3 confirms) — the explicit scope wins over auto-derived.
  const scopeState = useMemo(() => {
    const setEvt = [...events].reverse().find(e => e.type === "scope.set" || e.type === "scope.confirmed");
    const confirmed = events.some(e => e.type === "scope.confirmed");
    if (!setEvt) return null;
    const p = setEvt.payload as { hosts?: string[]; users?: string[]; techniques?: string[] };
    return { hosts: p.hosts ?? [], users: p.users ?? [], techniques: p.techniques ?? [], confirmed, by: setEvt.actor_id };
  }, [events]);
  const dispositions = useMemo(() => new Map(events.filter(e => e.type === "disposition.set").map(e => [String(e.payload.event_id), String(e.payload.verdict)])), [events]);
  // G-04b: per-row triage state for the shared feed badges (reflects the player's own
  // actions — claimed/dispositioned/escalated — never ground truth).
  const escalatedIds = useMemo(() => new Set(events.filter(e => e.type === "escalation.requested").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  const claimByEid = useMemo(() => {
    const m = new Map<string, { by: string; at: number }>();
    for (const e of events) {
      if (e.type !== "alert.claimed" && e.type !== "alert.released") continue;
      const eid = String((e.payload as { event_id?: string }).event_id); if (!eid) continue;
      if (e.type === "alert.released") m.delete(eid);
      else m.set(eid, { by: e.actor_id ?? "", at: e.occurred_at ? Date.parse(e.occurred_at) : Date.now() });
    }
    return m;
  }, [events]);
  const rowStatus = useCallback((rid?: string) => {
    if (!rid) return null;
    const key = rid.startsWith("ev_") ? rid.slice(3) : rid; // LiveEvent.id → sel-id scheme
    const disposed = dispositions.get(key);
    const c = claimByEid.get(key);
    const claimActive = !!c && !dispositions.has(key) && (Date.now() - c.at <= 5 * 60 * 1000);
    const claim: "me" | "other" | undefined = claimActive ? (c!.by === me?.id ? "me" : "other") : undefined;
    const escalated = escalatedIds.has(key);
    if (!disposed && !claim && !escalated) return null;
    return { disposed, claim, escalated };
  }, [dispositions, claimByEid, escalatedIds, me?.id]);
  const activity = useMemo(() => events.filter(e => ["escalation.requested", "escalation.acknowledged", "escalation.bounced", "escalation.resolved", "elevation.requested", "containment.requested", "containment.approved", "containment.denied", "containment.executed", "disposition.set", "hunt.logged", "rule.published", "intel.published", "handover.noted", "decision.logged", "sitrep.sent", "report.submitted", "evidence.pinned", "case.status_set", "case.assigned", "scope.set", "scope.confirmed", "staff.inject", "ticket.answered"].includes(e.type)), [events]);
  // The team feed rendered with the REAL dashboard EventFeed — enrich each shared
  // event into a LiveEvent so it looks and behaves exactly like the single-player
  // Live SOC dashboard (rule levels, source badges, raw formatting, threat-intel).
  // Normalise the required fields + guard each event so one malformed payload can
  // never crash the whole feed (real telemetry always has these; be defensive).
  const liveFeed = useMemo<LiveEvent[]>(() => feed.slice(-120).map((e, i) => {
    const p = e.payload as Record<string, unknown>;
    const norm = {
      ...p,
      id: typeof p.id === "string" ? p.id : `ev_${e.seq}`,
      ts: typeof p.ts === "string" ? p.ts : new Date().toISOString(),
      source: typeof p.source === "string" ? p.source : "siem",
      event_type: typeof p.event_type === "string" && p.event_type ? p.event_type : "informational",
      severity: typeof p.severity === "string" ? p.severity : "informational",
    } as unknown as TelemetryEvent;
    try { return enrichEvent(norm, i); }
    catch { return { ...norm, ruleLevel: 1, ruleId: "RULE-0000", displayDescription: asStr(p.description) || asStr(p.event_type) || "event" } as unknown as LiveEvent; }
  }), [feed]);
  // Distinct sources present in the feed → populate the G-04 source filter.
  const feedSources = useMemo(() => [...new Set(liveFeed.map(e => e.source).filter(Boolean))].sort(), [liveFeed]);

  // G-05: "Investigate in EDR" — reconstruct the SAME attack from the team feed's
  // endpoint telemetry (reusing the single-player builder) and deep-link into the
  // /edr console pre-loaded on the process tree. Returns null for pure identity/
  // cloud attacks with no endpoint telemetry → we tell the analyst instead of
  // opening an empty console.
  const openEdr = useCallback((description?: string) => {
    try {
      const evs = feed.map(e => e.payload as unknown as TelemetryEvent);
      const inv = buildInvestigationFromStory({ id: `team-${id}`, title: "Team incident — live", events: evs });
      if (!inv) { setNote("No endpoint (EDR/Sysmon) telemetry in this incident yet — nothing to open in the EDR console."); return; }
      // Put the escalated event's description in the EDR header, so the analyst
      // always sees WHAT they're investigating (not a generic "Team incident").
      if (description) inv.title = description;
      localStorage.setItem("edr_live_investigation", JSON.stringify(inv));
      const w = window.open(`/edr?case=live&team=${id}`, "_blank", "noopener");
      if (!w) { setNote("Pop-up blocked — allow pop-ups for this site, then click “Investigate in EDR” again."); }
    } catch { setNote("Couldn't open the EDR console for this incident."); }
  }, [feed, id]);

  if (loading) return <div className="flex items-center gap-2 p-6 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Loading…</div>;
  if (error && !session) return (
    <div className="p-6"><div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>
      <Link href="/team" className="mt-3 inline-flex items-center gap-1 text-sm text-cyber-300"><ArrowLeft className="h-4 w-4" /> Back</Link></div>
  );

  return (
    <div>
      <Topbar title={phase === "running" ? "Live team exercise" : "Team lobby"} subtitle={session ? `${session.company_id} · ${session.difficulty}` : ""} />
      <div className="container mx-auto max-w-[1100px] px-6 py-6 space-y-5">
        <Link href="/team" className="inline-flex items-center gap-1 text-xs text-slate-400 hover:text-white"><ArrowLeft className="h-3.5 w-3.5" /> Team training</Link>
        {error && <div className="flex items-center gap-2 rounded-lg border border-severity-high/40 bg-severity-high/10 px-4 py-3 text-sm text-severity-high"><AlertTriangle className="h-4 w-4" />{error}</div>}
        {note && phase !== "running" && <div className="rounded-lg border border-neon-green/30 bg-neon-green/10 px-4 py-3 text-sm text-neon-green">{note}</div>}

        {countdown !== null && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70">
            <div className="text-center"><p className="text-sm uppercase tracking-[0.3em] text-cyber-300">Exercise starts in</p><p className="mt-2 font-mono text-8xl font-black text-white">{countdown}</p></div>
          </div>
        )}

        {showGuide && me && <RoleGuideModal role={me.role} onClose={() => setShowGuide(false)} />}

        {/* Who-just-left popups — every member sees them when a teammate drops. */}
        {leftNotices.length > 0 && (
          <div className="fixed right-4 top-20 z-50 flex w-72 flex-col gap-2">
            {leftNotices.map(n => (
              <div key={n.key} className="flex items-start gap-2 rounded-lg border border-neon-amber/40 bg-bg-elevated px-3 py-2 shadow-lg">
                <UserMinus className="mt-0.5 h-4 w-4 shrink-0 text-neon-amber" />
                <p className="text-[12px] text-slate-200"><b>{n.name}</b> <span className="text-slate-400">({n.role})</span> left the session.</p>
                <button onClick={() => setLeftNotices(ns => ns.filter(x => x.key !== n.key))} className="ml-auto shrink-0 text-slate-500 hover:text-white"><X className="h-3.5 w-3.5" /></button>
              </div>
            ))}
          </div>
        )}

        {/* Training halted — a core role has nobody online. Blocks play until the
            team is back (auto-clears), or staff/Manager reassign / end. */}
        {haltActive && !haltDismissed && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 px-6">
            <div className="max-w-md rounded-xl border border-neon-amber/40 bg-bg-elevated p-6 text-center shadow-2xl">
              <PauseCircle className="mx-auto h-10 w-10 text-neon-amber" />
              <h3 className="mt-3 text-lg font-bold text-white">Training paused</h3>
              <p className="mt-1 text-sm text-neon-amber">{haltMessage}</p>
              <p className="mt-2 text-[12px] text-slate-400">{pausedReason === "manual"
                ? "The instructor paused the shift. It stays paused until they resume it."
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

        {/* ── LOBBY ── */}
        {phase === "lobby" && (
          <>
            {/* Mission briefing — objectives + how you're scored, up front (no spoilers) */}
            <Card className="border-cyber-500/30">
              <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-cyber-300" /> Shift briefing</h2>
              <p className="mt-1 text-xs text-slate-400">A live SOC shift on a shared feed — expect a mix of noise and real activity. ~30–45 min. Work as one team, tier to tier.</p>
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
              <p className="mt-2 text-[10px] text-slate-500">Scored per role on a visible 0/4/8/12 rubric (accuracy · timeliness · coordination). No hidden scoring; the debrief shows exactly how each call landed.</p>
            </Card>
            <Card>
              <div className="flex items-center justify-between">
                <h2 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" /> Team roster</h2>
                <span className="font-mono text-xs text-slate-400">{players.filter(p => readyMap[p.user_id]).length}/{players.length} ready</span>
              </div>
              <div className="mt-3 space-y-1.5">
                {roster.map(m => {
                  const isOn = online.has(m.user_id); const rdy = !!readyMap[m.user_id]; const isMe = me?.id === m.user_id;
                  return (
                    <div key={m.user_id} className={`flex items-center gap-3 rounded-lg border px-3 py-2 ${rdy ? "border-neon-green/30 bg-neon-green/[0.05]" : "border-border"}`}>
                      <span className={`h-2 w-2 shrink-0 rounded-full ${isOn ? "bg-neon-green" : "bg-slate-600"}`} title={isOn ? "connected" : "not connected"} />
                      <span className="min-w-0 flex-1 truncate text-sm text-slate-200">{m.name}{isMe && <span className="ml-1 text-[11px] text-cyber-300">(you)</span>}
                        <span className="ml-2 rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{ROLE_LABEL[m.role] ?? m.role}</span></span>
                      {m.role === "instructor" ? <span className="inline-flex items-center gap-1 text-[11px] text-neon-amber"><ShieldCheck className="h-3.5 w-3.5" /> runs it</span>
                        : rdy ? <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-neon-green"><CheckCircle2 className="h-3.5 w-3.5" /> ready</span>
                        : <span className="inline-flex items-center gap-1 text-[11px] text-slate-500"><Circle className="h-3.5 w-3.5" /> not ready</span>}
                    </div>
                  );
                })}
              </div>
            </Card>

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
                  <div><p className="text-sm font-bold text-white">Start the exercise</p><p className="text-xs text-slate-400">{allReady ? "All players are ready." : "Locked until every player marks ready."}</p></div>
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
            <div className="flex items-center gap-2 text-sm text-neon-green">
              <Radio className="h-4 w-4 animate-pulse" /> Live — same feed for the whole team
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
              <button onClick={() => setShowGuide(true)} className="ml-auto shrink-0 text-[11px] text-cyber-300 underline-offset-2 hover:underline">how my role works →</button>
            </div>

            {/* Silent-failure nudge (F6): attack active, nobody escalated yet */}
            {guidingNudgeMins != null && me.role !== "instructor" && me.role !== "observer" && (
              <div className="flex items-start gap-2 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-3 py-2 text-sm">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-neon-amber" />
                <span className="text-neon-amber">Heads up — high-signal activity has been in the feed for ~{guidingNudgeMins} min with <b>no escalation yet</b>. Is the team watching the right log? Triage it and escalate if it&apos;s real.</span>
              </div>
            )}

            {/* Shared case — the team's single shared truth; collapsible summary bar (G-02) */}
            <SharedCase events={events} feed={feed} roster={roster} me={me} act={act} nameOf={nameOf} />

            <div className="grid gap-4 lg:grid-cols-[1fr_380px]">
              {/* Left column: raw feed for analysts; a summaries-only Situation Board
                  for Lead/Mgr — §3.7 keeps coordinators OUT of raw (G-08). Staff
                  keep the raw feed for oversight. */}
              <div className="min-w-0 space-y-2">
                {((me.role === "lead" || me.role === "mgr") && !me.is_staff) ? (
                  <SituationBoard liveFeed={liveFeed} events={events} feed={feed} nameOf={nameOf} />
                ) : (
                  <>
                    {/* G-04: surfaced feed filters + active click-to-pivot chips */}
                    <FeedFilterBar
                      severity={fSeverity} setSeverity={setFSeverity}
                      source={fSource} setSource={setFSource} sources={feedSources}
                      search={fSearch} setSearch={setFSearch}
                      pivots={[["user", fUser, setFUser], ["host", fHost, setFHost], ["ip", fIp, setFIp]]}
                    />
                    <EventFeed
                      events={liveFeed}
                      severityFilter={fSeverity} sourceFilter={fSource} search={fSearch}
                      userFilter={fUser} hostFilter={fHost} ipFilter={fIp}
                      onRowOpened={(eid, dwellMs) => act("event.opened", { event_id: eid, dwell_ms: dwellMs })}
                      onPivot={(field, value) => { if (field === "user") setFUser(value); else if (field === "host") setFHost(value); else setFIp(value); }}
                      onAddIoc={me.role === "t1" ? (value) => setIocDraft(d => d.some(x => x.value.toLowerCase() === value.toLowerCase()) ? d : [...d, { type: detectIocType(value), value, source: "picked" }]) : undefined}
                      rowStatus={rowStatus}
                      onEscalate={me.role === "t1" ? (ev) => {
                        // Map the LiveEvent back to T1Console's sel id (same scheme as the dropdown).
                        const raw = feed.find(f => {
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
                      } : undefined}
                    />
                  </>
                )}
              </div>
              {/* YOUR ROLE — the dominant role panel(s), then secondary panels tabbed (G-03) */}
              <div className="space-y-4">
                {me.role === "t1" && <T1Console feed={feed} dispositions={dispositions} events={events} meId={me.id} iocDraft={iocDraft} setIocDraft={setIocDraft} nameOf={nameOf} act={act} sel={t1Sel} setSel={setT1Sel} reportOpen={t1ReportOpen} setReportOpen={setT1ReportOpen} />}
                {(me.role === "t2" || me.role === "t3") && <T2Console role={me.role} meId={me.id} escalations={escalations} acked={acked} ackedBy={ackedBy} escBounced={escBounced} escResolved={escResolved} reportedIds={reportedIds} reportByEid={reportByEid} elevatedIds={elevatedIds} contReq={contReq} contApproved={contApproved} contExecuted={contExecuted} scope={scopeState} nameOf={nameOf} act={act} onEdr={openEdr} onPivot={(field, value) => { if (field === "user") setFUser(value); else if (field === "host") setFHost(value); else setFIp(value); }} />}
                {me.role === "t3" && <HuntConsole scope={scopeState} elevations={elevations} elevAcked={elevAcked} nameOf={nameOf} act={act} onEdr={openEdr} onPivot={(field, value) => { if (field === "user") setFUser(value); else if (field === "host") setFHost(value); else setFIp(value); }} />}
                {/* SOC Manager now holds the coordinator authority (approve containment,
                    decision log, SITREP) as well as shift management. 'lead'/'de'/'ti'
                    branches stay for backward-compatibility with older sessions. */}
                {(me.role === "lead" || me.role === "mgr") && <LeadConsole contReq={contReq} contDecided={contDecided} escalations={escalations} acked={acked} events={events} nameOf={nameOf} act={act} />}
                {me.role === "de" && <DEConsole liveFeed={liveFeed} events={events} act={act} />}
                {me.role === "ti" && <TIConsole act={act} />}
                {me.role === "mgr" && <MgrConsole roster={roster} events={events} act={act} />}
                {me.role === "instructor" && <InstructorPanel sessionId={id} roster={roster} online={online} events={events} act={act} />}
                {/* G-14: injects / announcements / help-desk tickets — visible to everyone */}
                <InjectFeed events={events} me={me} nameOf={nameOf} act={act} />
                {/* Shared context every role can consult, but folded so the role panel stays dominant */}
                <SecondaryPanels events={events} activity={activity} me={me} nameOf={nameOf} act={act} />
              </div>
            </div>
          </>
        )}

        {phase === "ended" && me && (
          <>
            {endReason === "owner_left" && <div className="flex items-center gap-2 rounded-lg border border-neon-amber/40 bg-neon-amber/[0.08] px-4 py-3 text-sm text-neon-amber"><LogOut className="h-4 w-4 shrink-0" /> The session owner (instructor) left the live room, so the session was closed automatically.</div>}
            <TeamReport events={events} roster={roster} me={me} />
          </>
        )}
      </div>
    </div>
  );
}

// ── Shared Case panel (§5.1) — the one artifact the whole team works ──────────
const CASE_STATUSES = ["new", "triaged", "investigating", "contained", "eradicated", "closed"];
function sevRank(s?: string) { return s === "critical" ? 4 : s === "high" ? 3 : s === "medium" ? 2 : 1; }
function SharedCase({ events, feed, roster, me, act, nameOf }: { events: Ev[]; feed: Ev[]; roster: RosterMember[]; me: Me; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; nameOf: (u: string | null) => string }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false); // G-02: collapsed to a summary bar by default
  const feedById = useMemo(() => new Map(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.payload as Record<string, unknown>])), [feed]);
  const escs = useMemo(() => events.filter(e => e.type === "escalation.requested"), [events]);
  const notes = useMemo(() => events.filter(e => e.type === "note.added"), [events]);
  // A1: the latest Tier-2 incident report per case — the live handover the team reads.
  const reportsByEid = useMemo(() => {
    const m = new Map<string, Ev>();
    for (const e of events) if (e.type === "report.submitted") m.set(String((e.payload as { event_id?: string }).event_id), e);
    return m;
  }, [events]);
  const reports = useMemo(() => [...reportsByEid.values()], [reportsByEid]);
  const statusEvt = useMemo(() => [...events].reverse().find(e => e.type === "case.status_set"), [events]);
  const ownerEvt = useMemo(() => [...events].reverse().find(e => e.type === "case.assigned"), [events]);

  const autoStatus = escs.length > 0 ? "investigating" : "new";
  const status = (statusEvt?.payload as { status?: string })?.status ?? autoStatus;
  const ownerId = (ownerEvt?.payload as { owner?: string })?.owner ?? null;

  // Scope builds itself from what Tier-1 escalated — resolve each escalated event
  // back to its feed log and union the hosts/users/techniques it touched.
  const hosts = new Set<string>(), users = new Set<string>(), techs = new Set<string>();
  let maxSev = "low";
  for (const esc of escs) {
    const pp = esc.payload as { event_id?: string };
    const fe = feedById.get(String(pp.event_id)) as { hostname?: string; severity?: string; mitre_technique?: string; user?: { email?: string; full_name?: string }; user_email?: string } | undefined;
    if (typeof fe?.hostname === "string" && fe.hostname) hosts.add(fe.hostname);
    if (typeof fe?.mitre_technique === "string" && fe.mitre_technique) techs.add(fe.mitre_technique);
    const u = fe?.user?.email || fe?.user?.full_name || fe?.user_email; if (typeof u === "string" && u) users.add(u);
    if (typeof fe?.severity === "string" && sevRank(fe.severity) > sevRank(maxSev)) maxSev = fe.severity;
  }
  const severity = (statusEvt?.payload as { severity?: string })?.severity ?? maxSev;
  // G-10: an explicit scope (T2 set / T3 confirmed) overrides the auto-derived union.
  const scopeEvt = useMemo(() => [...events].reverse().find(e => e.type === "scope.set" || e.type === "scope.confirmed"), [events]);
  const scopeConfirmed = useMemo(() => events.some(e => e.type === "scope.confirmed"), [events]);
  const explicitScope = scopeEvt ? (scopeEvt.payload as { hosts?: string[]; users?: string[]; techniques?: string[] }) : null;
  const dispHosts = explicitScope ? (explicitScope.hosts ?? []) : [...hosts];
  const dispUsers = explicitScope ? (explicitScope.users ?? []) : [...users];
  const dispTechs = explicitScope ? (explicitScope.techniques ?? []) : [...techs];
  const scopeLabel = explicitScope ? (scopeConfirmed ? "confirmed by Tier-3" : "proposed by Tier-2") : "auto-derived";
  // G-09: executed isolations (shared containment state / real MTTC).
  const executed = useMemo(() => events.filter(e => e.type === "containment.executed"), [events]);
  const canStatus = ["t2", "t3", "lead", "mgr"].includes(me.role ?? "");
  const canAssign = ["lead", "mgr"].includes(me.role ?? "");
  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");

  async function addNote() { if (note.trim().length < 3) return; setBusy(true); const ok = await act("note.added", { text: note }); setBusy(false); if (ok) setNote(""); }

  return (
    <Card>
      {/* G-02: thin collapsible summary bar — status·sev·owner·scope·evidence — the
          feed stays the team's primary truth; the case opens to full detail on click */}
      <button onClick={() => setOpen(o => !o)} className="flex w-full flex-wrap items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 shrink-0 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Shared case</h2>
        <span className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${status === "closed" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : status === "contained" || status === "eradicated" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"}`}>{status}</span>
        <span className={`rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase ${sevRank(severity) >= 3 ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>sev {severity}</span>
        <span className="hidden font-mono text-[10px] text-slate-500 sm:inline">{dispHosts.length}h · {dispUsers.length}u · {dispTechs.length}t · {escs.length} ev{executed.length ? ` · ${executed.length} isolated` : ""}</span>
        <span className="ml-auto text-[11px] text-slate-400">owner: <span className="text-slate-200">{ownerId ? nameOf(ownerId) : "unassigned"}</span></span>
      </button>

      {open && (<>
      {/* Plain explanation — the case was opaque to new players (feedback) */}
      <p className="mt-2 text-[11px] leading-relaxed text-slate-400">
        The team&apos;s <b className="text-slate-300">single source of truth</b> for this incident — it builds itself from what Tier-1 escalates. Move the <b className="text-slate-300">status</b> as the incident progresses (new → investigating → contained → closed); the SOC Manager assigns an <b className="text-slate-300">owner</b>; scope, evidence and isolations roll up here so everyone shares one picture.
      </p>
      {/* lifecycle stepper */}
      <div className="mt-3 flex flex-wrap items-center gap-1">
        {CASE_STATUSES.map(s => (
          <button key={s} disabled={!canStatus || busy || s === status}
            onClick={async () => { setBusy(true); await act("case.status_set", { status: s, severity }); setBusy(false); }}
            className={`rounded-md border px-2 py-1 text-[10px] font-semibold uppercase tracking-wider transition ${s === status ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300" : canStatus ? "border-border text-slate-400 hover:text-white" : "border-border/50 text-slate-600"}`}>{s}</button>
        ))}
      </div>
      {canAssign && (
        <div className="mt-2">
          <select value={ownerId ?? ""} onChange={async e => { setBusy(true); await act("case.assigned", { owner: e.target.value }); setBusy(false); }}
            className="rounded-lg border border-border bg-bg px-2 py-1 text-xs text-slate-200 focus:outline-none">
            <option value="">assign owner…</option>
            {players.map(p => <option key={p.user_id} value={p.user_id}>{p.name} · {ROLE_LABEL[p.role] ?? p.role}</option>)}
          </select>
        </div>
      )}

      {/* scope — explicit T2/T3 scope when set (G-10), else auto-derived from escalations */}
      <div className="mt-3 flex items-center justify-between">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Scope</p>
        <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${scopeConfirmed ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : explicitScope ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-500"}`}>{scopeLabel}</span>
      </div>
      <div className="mt-1 grid gap-2 sm:grid-cols-3">
        <ScopeBox label="Hosts" items={dispHosts} />
        <ScopeBox label="Users" items={dispUsers} />
        <ScopeBox label="Techniques" items={dispTechs} accent />
      </div>
      {executed.length > 0 && (
        <div className="mt-2 flex items-center gap-2 rounded border border-neon-green/30 bg-neon-green/[0.06] px-2 py-1 text-[11px] text-neon-green">
          <ShieldCheck className="h-3.5 w-3.5 shrink-0" /> Isolation executed: {executed.map(e => asStr((e.payload as { target?: string }).target)).filter(Boolean).join(", ") || `${executed.length} host(s)`}
        </div>
      )}

      {/* evidence = the escalations — the case builds itself as tickets rise */}
      <div className="mt-3">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Evidence ({escs.length})</p>
        {escs.length === 0 ? <p className="text-xs text-slate-500">No escalations yet — when Tier-1 escalates a log, it lands here as case evidence, and the scope above fills in.</p> : (
          <div className="space-y-1">
            {escs.map(e => { const p = e.payload as { what?: string; event_id?: string }; const fe = feedById.get(String(p.event_id)) as { severity?: string } | undefined; return (
              <div key={e.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-xs">
                <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevColor(fe?.severity)}`} />
                <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(p.what) || "escalation"}</span>
                <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</span>
              </div>
            ); })}
          </div>
        )}
      </div>

      {/* A1: Tier-2 determinations & handover reports — read live by T3 and the Manager */}
      {reports.length > 0 && (
        <div className="mt-3">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Determinations &amp; handover ({reports.length})</p>
          <div className="space-y-1.5">
            {reports.map(e => { const p = e.payload as { verdict?: string; summary?: string; recommendation?: string; findings?: string }; const v = asStr(p.verdict); return (
              <div key={e.seq} className="rounded-lg border border-cyber-500/25 bg-cyber-500/[0.05] px-2.5 py-1.5 text-xs">
                <div className="flex items-center gap-2">
                  {v && <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${v === "true_positive" || v === "escalate" ? "border-severity-high/40 bg-severity-high/10 text-severity-high" : "border-border text-slate-400"}`}>{v.replace("_", " ")}</span>}
                  <span className="min-w-0 flex-1 truncate text-slate-200">{asStr(p.summary) || "incident report"}</span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</span>
                </div>
                {asStr(p.recommendation) && <p className="mt-0.5 text-[11px] text-cyber-200"><span className="text-slate-500">▶ recommends:</span> {asStr(p.recommendation)}</p>}
              </div>
            ); })}
          </div>
        </div>
      )}

      {/* case notes */}
      <div className="mt-3 border-t border-border/50 pt-2">
        <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Case notes ({notes.length})</p>
        {notes.length > 0 && (
          <div className="mb-2 max-h-40 space-y-1 overflow-y-auto">
            {notes.slice().reverse().map(e => <p key={e.seq} className="whitespace-pre-wrap break-words text-xs text-slate-300"><span className="font-medium text-slate-200">{nameOf(e.actor_id)}:</span> {String((e.payload as { text?: string }).text ?? "").slice(0, 2000)}</p>)}
          </div>
        )}
        <div className="flex gap-2">
          <input value={note} onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter") addNote(); }} placeholder="Add a case note…" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <Button variant="outline" size="sm" disabled={busy || note.trim().length < 3} onClick={addNote}>Add</Button>
        </div>
      </div>
      </>)}
    </Card>
  );
}
function ScopeBox({ label, items, accent }: { label: string; items: string[]; accent?: boolean }) {
  return (
    <div className="rounded-lg border border-border bg-bg px-2 py-1.5">
      <p className="text-[10px] uppercase tracking-wider text-slate-400">{label}</p>
      {items.length === 0 ? <p className="text-[11px] text-slate-600">—</p> : (
        <div className="mt-1 flex flex-wrap gap-1">{items.slice(0, 8).map(i => <span key={i} className={`rounded px-1.5 py-0.5 font-mono text-[10px] ${accent ? "bg-cyber-500/10 text-cyber-300" : "bg-white/5 text-slate-300"}`}>{i}</span>)}</div>
      )}
    </div>
  );
}

// ── Shared feed ──────────────────────────────────────────────────────────────
function sevColor(s?: string) { return s === "critical" || s === "high" ? "bg-severity-high" : s === "medium" ? "bg-neon-amber" : "bg-slate-500"; }
/** Some vendor events carry `description`/`raw` as an OBJECT, not a string — React
 *  can't render an object child, so coerce everything we render to a safe string. */
function asStr(v: unknown): string { return typeof v === "string" ? v : ""; }
/** Enrich an escalation's event snapshot into a LiveEvent so Tier-2 can open the
 * FULL original log (raw fields, MITRE, pivot) — defensive like the team feed. */
function enrichSnapshot(snap: Record<string, unknown> | undefined): LiveEvent | null {
  if (!snap || typeof snap !== "object") return null;
  const norm = {
    ...snap,
    id: typeof snap.id === "string" ? snap.id : "snap",
    ts: typeof snap.ts === "string" ? snap.ts : new Date().toISOString(),
    source: typeof snap.source === "string" ? snap.source : "siem",
    event_type: typeof snap.event_type === "string" && snap.event_type ? snap.event_type : "informational",
    severity: typeof snap.severity === "string" ? snap.severity : "informational",
  } as unknown as TelemetryEvent;
  try { return enrichEvent(norm, 0); }
  catch { return { ...norm, ruleLevel: 1, ruleId: "RULE-0000", displayDescription: asStr(snap.description) || asStr(snap.event_type) || "event" } as unknown as LiveEvent; }
}

// ── T1 console: pick a log → disposition + structured escalation report ───────
const REQUESTED_ACTIONS = ["investigate", "contain", "monitor", "escalate-to-mgr"];
const SEVERITIES = ["low", "medium", "high", "critical"];
const MIN_RATIONALE_WORDS = 12; // T1-6 hard gate: "meaningful rationale"
type Ioc = { type: string; value: string; source: "picked" | "manual" };
/** Auto-detect an IOC's type for display + accuracy scoring (T1-5). */
function detectIocType(v: string): string {
  const s = v.trim();
  if (/^[a-f0-9]{64}$/i.test(s)) return "sha256";
  if (/^[a-f0-9]{40}$/i.test(s)) return "sha1";
  if (/^[a-f0-9]{32}$/i.test(s)) return "md5";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return "ip";
  if (/@/.test(s)) return "email";
  if (/\.[a-z]{2,}$/i.test(s) && !/\s/.test(s)) return "domain";
  return "host";
}
// A4: a MANUAL IOC must be a real indicator shape — a strong type (hash/ip/email/domain)
// or a plausible hostname (has a hyphen/dot/digit, no spaces) — so junk free text like
// "asdf" can't satisfy the ≥1-indicator escalation gate. Picked-from-log IOCs are trusted.
function isValidIoc(v: string): boolean {
  const s = v.trim();
  if (!s || /\s/.test(s)) return false;
  if (detectIocType(s) !== "host") return true;       // hash / ip / email / domain
  return /^[A-Za-z0-9][A-Za-z0-9._-]{2,62}$/.test(s) && /[-.\d]/.test(s); // plausible hostname
}
const wordCount = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;

function T1Console({ feed, dispositions, events, meId, iocDraft, setIocDraft, nameOf, act, sel, setSel, reportOpen, setReportOpen }: {
  feed: Ev[]; dispositions: Map<string, string>; events: Ev[]; meId: string;
  iocDraft: Ioc[]; setIocDraft: React.Dispatch<React.SetStateAction<Ioc[]>>;
  nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>;
  // sel + reportOpen live in the parent so the 🚩 button on a LOG (in the feed's
  // DetailPanel) can select that event and open this report modal directly.
  sel: string; setSel: (v: string) => void; reportOpen: boolean; setReportOpen: (v: boolean) => void;
}) {
  const [form, setForm] = useState({ summary: "", observations: "", assessment: "", requested_action: "investigate", severity: "medium" });
  const [iocText, setIocText] = useState("");
  const [busy, setBusy] = useState(false);
  const selDisp = sel ? dispositions.get(sel) : undefined;
  const isLowConf = selDisp === "suspicious"; // T1-2: Suspicious → low-confidence lead

  // T1-3: soft-lock claims — latest alert.claimed/released per event wins; a claim
  // is active for ~5 min unless released or the alert was dispositioned.
  const CLAIM_TTL = 5 * 60 * 1000;
  const claims = useMemo(() => {
    const m = new Map<string, { by: string; at: number }>();
    for (const e of events) {
      if (e.type !== "alert.claimed" && e.type !== "alert.released") continue;
      const eid = String((e.payload as { event_id?: string }).event_id); if (!eid) continue;
      if (e.type === "alert.released") m.delete(eid);
      else m.set(eid, { by: e.actor_id ?? "", at: e.occurred_at ? Date.parse(e.occurred_at) : Date.now() });
    }
    return m;
  }, [events]);
  const claimerOf = (eid: string): { by: string; at: number } | null => {
    const c = claims.get(eid); if (!c) return null;
    if (dispositions.has(eid)) return null;              // dispositioned → off the clock
    if (Date.now() - c.at > CLAIM_TTL) return null;       // stale claim expired
    return c;
  };
  const options = feed.map(e => {
    const p = e.payload as { id?: string; description?: unknown; event_type?: unknown }; const id = String(p.id ?? e.seq);
    const c = claimerOf(id); const lock = c && c.by !== meId ? "🔒 " : "";
    return { id, label: `${lock}#${e.seq} ${asStr(p.description) || asStr(p.event_type) || "event"}` };
  });
  const selClaim = sel ? claimerOf(sel) : null;
  async function claim() { if (!sel) return; setBusy(true); await act("alert.claimed", { event_id: sel }); setBusy(false); }
  async function release() { if (!sel) return; setBusy(true); await act("alert.released", { event_id: sel }); setBusy(false); }

  // T1-7: my escalations with live status (sent → acknowledged → bounced/resolved).
  const myEsc = useMemo(() => {
    const acked = new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id)));
    const bounced = new Set(events.filter(e => e.type === "escalation.bounced").map(e => String((e.payload as { event_id?: string }).event_id)));
    const resolved = new Set(events.filter(e => e.type === "escalation.resolved").map(e => String((e.payload as { event_id?: string }).event_id)));
    return events.filter(e => e.type === "escalation.requested" && e.actor_id === meId).map(e => {
      const p = e.payload as { event_id?: string; summary?: string; what?: string; reason?: string }; const eid = String(p.event_id);
      const status = resolved.has(eid) ? "resolved" : bounced.has(eid) ? "bounced" : acked.has(eid) ? "acknowledged" : "sent";
      const reason = asStr((events.filter(e2 => e2.type === "escalation.bounced" && String((e2.payload as { event_id?: string }).event_id) === eid).slice(-1)[0]?.payload as { reason?: string } | undefined)?.reason);
      return { seq: e.seq, eid, label: asStr(p.summary) || asStr(p.what) || "escalation", status, reason };
    });
  }, [events, meId]);

  const [iocErr, setIocErr] = useState("");
  function addIoc(value: string, source: "picked" | "manual") {
    const v = value.trim(); if (!v) return;
    // A4: a MANUAL indicator must look like a real IOC; picked-from-log values are trusted.
    if (source === "manual" && !isValidIoc(v)) { setIocErr(`"${v}" isn't a valid indicator (hash / IP / domain / email / hostname).`); return; }
    setIocErr("");
    setIocDraft(d => d.some(x => x.value.toLowerCase() === v.toLowerCase()) ? d : [...d, { type: detectIocType(v), value: v, source }]);
  }
  const rationaleWords = wordCount(form.observations);
  // T1-6 quality gate — every condition must hold before Escalate is allowed.
  const gate = {
    summary: !!form.summary.trim(),
    rationale: rationaleWords >= MIN_RATIONALE_WORDS,
    ioc: iocDraft.length >= 1,
    severity: !!form.severity,
    // A4: escalate only an attack-ish call — you can't escalate a log you marked benign/FP.
    disposition: selDisp === "true_positive" || selDisp === "suspicious",
  };
  const canEscalate = !!sel && !busy && gate.summary && gate.rationale && gate.ioc && gate.severity && gate.disposition;

  // When the report opens (from the 🚩 on a log OR the dropdown button), take the
  // soft-claim automatically so two Tier-1s don't work the same log — unless a
  // teammate already holds it (then the modal shows a "Take over" banner instead).
  useEffect(() => {
    if (reportOpen && sel && !selClaim) { act("alert.claimed", { event_id: sel }); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reportOpen, sel]);

  async function disp(v: string) {
    if (!sel) return; setBusy(true); await act("disposition.set", { event_id: sel, verdict: v }); setBusy(false);
    // FP/Benign close at T1 and release any soft claim so a teammate can reuse the row.
    if (v === "false_positive" || v === "benign") await act("alert.released", { event_id: sel });
  }
  async function escalate() {
    if (!canEscalate) return;
    setBusy(true);
    // Carry the FULL original log with the escalation so Tier-2 investigates the
    // real event (all raw fields), not just T1's words — and independent of feed state.
    const snapshot = feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel)?.payload as Record<string, unknown> | undefined;
    const fe = snapshot as { hostname?: string; user_email?: string; user?: { email?: string } } | undefined;
    const entity = asStr(fe?.hostname) || asStr(fe?.user_email) || asStr(fe?.user?.email) || "the affected asset";
    const ok = await act("escalation.requested", {
      event_id: sel, summary: form.summary, observations: form.observations, assessment: form.assessment,
      iocs: iocDraft, requested_action: form.requested_action, severity: form.severity,
      confidence: isLowConf ? 0.3 : 0.7, low_confidence: isLowConf || undefined,
      hostname: asStr(fe?.hostname) || undefined, entity, snapshot,
      what: form.summary, why: form.observations, // back-compat aliases
    });
    if (ok) await act("alert.released", { event_id: sel }); // escalated → hand off the claim
    setBusy(false);
    if (ok) { setForm({ summary: "", observations: "", assessment: "", requested_action: "investigate", severity: "medium" }); setIocDraft([]); setSel(""); setReportOpen(false); }
  }
  // The selected log's payload — powers the modal's log-summary header + the escalate snapshot.
  const selRaw = sel ? feed.find(e => String((e.payload as { id?: string }).id ?? e.seq) === sel) : undefined;
  const selP = selRaw?.payload as { id?: string; description?: unknown; event_type?: unknown; hostname?: unknown; user_email?: unknown; user?: { email?: unknown }; severity?: unknown; source?: unknown } | undefined;
  const selDesc = asStr(selP?.description) || asStr(selP?.event_type) || "event";
  const selHost = asStr(selP?.hostname);
  const selUser = asStr(selP?.user_email) || asStr(selP?.user?.email);
  const selSev = asStr(selP?.severity);
  const selSource = asStr(selP?.source);
  return (
    <>
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Tier-1 triage</h3>
      <p className="mt-1 text-[11px] text-slate-400">Open a log in the feed and hit <span className="font-semibold text-amber-300">🚩 Escalate this log</span> — or pick one below.</p>

      {/* T1-7: my escalations + status tracking (sent/ack/bounced/resolved) */}
      {myEsc.length > 0 && (
        <div className="mt-2 space-y-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">My escalations ({myEsc.length})</p>
          {myEsc.slice().reverse().slice(0, 6).map(e => (
            <div key={e.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-[11px]">
              <span className="min-w-0 flex-1 truncate text-slate-300">{e.label}{e.status === "bounced" && e.reason ? ` — ${e.reason}` : ""}</span>
              <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${e.status === "resolved" ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : e.status === "bounced" ? "border-neon-amber/40 bg-neon-amber/10 text-neon-amber" : e.status === "acknowledged" ? "border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border-border text-slate-400"}`}>{e.status}</span>
            </div>
          ))}
        </div>
      )}

      <label className="mt-3 block text-xs">
        <span className="mb-1 block uppercase tracking-wider text-slate-400">Pick a log</span>
        <select value={sel} onChange={e => setSel(e.target.value)} className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 focus:border-cyber-500/50 focus:outline-none">
          <option value="">— select an event —</option>
          {options.map(o => <option key={o.id} value={o.id}>{o.label}{dispositions.get(o.id) ? ` · ${dispositions.get(o.id)}` : ""}</option>)}
        </select>
      </label>
      {/* T1-3: soft-claim so two Tier-1 analysts don't work the same alert */}
      {sel && (
        selClaim && selClaim.by !== meId
          ? <div className="mt-2 flex items-center gap-2 rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1 text-[11px]">
              <span className="text-neon-amber">🔒 claimed by {nameOf(selClaim.by)}</span>
              <Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={claim}>Take over</Button>
            </div>
          : selClaim && selClaim.by === meId
            ? <div className="mt-2 flex items-center gap-2 text-[11px] text-neon-green"><span>✓ you claimed this alert</span><Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={release}>Release</Button></div>
            : <div className="mt-2"><Button variant="outline" size="sm" disabled={busy} onClick={claim}>Take this alert</Button></div>
      )}
      {/* T1-2: four dispositions incl. Suspicious */}
      <div className="mt-2 flex flex-wrap gap-1.5">
        {[["true_positive", "true positive"], ["false_positive", "false positive"], ["benign", "benign"], ["suspicious", "suspicious"]].map(([v, label]) => (
          <Button key={v} variant={selDisp === v ? "primary" : "outline"} size="sm" disabled={!sel || busy} onClick={() => disp(v)}>{label}</Button>
        ))}
      </div>

      {/* Open the escalation report for the selected log (same modal the 🚩 button opens) */}
      <div className="mt-3 border-t border-border/50 pt-3">
        <Button variant="primary" size="sm" className="w-full" disabled={!sel} onClick={() => setReportOpen(true)}>
          <ArrowUpRight className="mr-1.5 h-4 w-4" /> Write escalation report{sel ? ` — #${selRaw?.seq}` : ""}
        </Button>
        {!sel && <p className="mt-1 text-[10px] text-slate-500">Select a log first (feed 🚩 or the dropdown above).</p>}
      </div>
    </Card>

    {/* ── Escalation report modal — opens ON the log (🚩) or via "Write escalation report" ── */}
    {reportOpen && sel && (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4" onClick={() => setReportOpen(false)}>
        <div className="max-h-[88vh] w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-bg-elevated p-5" onClick={e => e.stopPropagation()}>
          <div className="flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-base font-bold text-white"><span className="text-lg leading-none">🚩</span> Escalation report → Tier-2</h2>
            <button onClick={() => setReportOpen(false)} aria-label="Close" className="text-xl leading-none text-slate-400 hover:text-white">&times;</button>
          </div>

          {/* Which log you're reporting on — pulled straight from the flagged event */}
          <div className="mt-3 rounded-lg border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-300/80">Flagged log · #{selRaw?.seq}</p>
            <p className="mt-0.5 text-sm text-slate-200">{selDesc}</p>
            <div className="mt-1 flex flex-wrap gap-1.5 text-[10px]">
              {selSev && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">severity: {selSev}</span>}
              {selSource && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">{selSource}</span>}
              {selHost && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">host: {selHost}</span>}
              {selUser && <span className="rounded border border-border bg-bg px-1.5 py-0.5 font-mono text-slate-300">user: {selUser}</span>}
            </div>
          </div>

          {/* Claim status — surfaced INSIDE the modal so the 🚩 path can't hide a teammate's lock */}
          {selClaim && selClaim.by !== meId ? (
            <div className="mt-2 flex items-center gap-2 rounded border border-neon-amber/40 bg-neon-amber/[0.08] px-2 py-1.5 text-[11px]">
              <span className="text-neon-amber">🔒 {nameOf(selClaim.by)} is already working this alert.</span>
              <Button variant="outline" size="sm" className="ml-auto" disabled={busy} onClick={claim}>Take over</Button>
            </div>
          ) : selClaim && selClaim.by === meId ? (
            <p className="mt-2 text-[11px] text-neon-green">✓ you claimed this alert</p>
          ) : null}

          {/* Disposition — triage before escalate. Set it right here if it isn't yet. */}
          <div className="mt-2">
            {selDisp ? (
              <p className="text-[11px] text-slate-400">Disposition: <span className="font-semibold text-slate-200">{selDisp.replace("_", " ")}</span></p>
            ) : (
              <>
                <p className="text-[11px] text-neon-amber">Set a disposition first (triage → escalate):</p>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {[["true_positive", "true positive"], ["suspicious", "suspicious"]].map(([v, label]) => (
                    <Button key={v} variant="outline" size="sm" disabled={busy} onClick={() => disp(v)}>{label}</Button>
                  ))}
                </div>
              </>
            )}
          </div>

          <div className="mt-3 space-y-2">
            {isLowConf && <p className="rounded border border-neon-amber/30 bg-neon-amber/[0.06] px-2 py-1 text-[11px] text-neon-amber">Low-confidence lead — sending to Tier-2 for a second look.</p>}
            <input value={form.summary} onChange={e => setForm(f => ({ ...f, summary: e.target.value }))} placeholder="Summary — one line: what happened + on what" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <textarea value={form.observations} onChange={e => setForm(f => ({ ...f, observations: e.target.value }))} placeholder={`Observations — the process/sequence/evidence (≥ ${MIN_RATIONALE_WORDS} words)`} rows={3} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            {/* T1-5: IOCs — pre-seeded from the flagged log; click "+IOC" on raw fields, or type here */}
            <div className="rounded-lg border border-border bg-bg px-2 py-1.5">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Indicators (IOCs) — click ＋IOC on the log&apos;s fields, or add below</p>
              {iocDraft.length > 0 && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {iocDraft.map(i => (
                    <span key={i.value} className="inline-flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 font-mono text-[10px] text-cyber-300">
                      <span className="text-slate-500">{i.type}:</span>{i.value}
                      <button onClick={() => setIocDraft(d => d.filter(x => x.value !== i.value))} className="text-slate-400 hover:text-white"><X className="h-3 w-3" /></button>
                    </span>
                  ))}
                </div>
              )}
              <div className="mt-1 flex gap-1.5">
                <input value={iocText} onChange={e => setIocText(e.target.value)} onKeyDown={e => { if (e.key === "Enter") { addIoc(iocText, "manual"); setIocText(""); } }} placeholder="add an IOC (ip / domain / hash / user)…" className="flex-1 rounded border border-border bg-bg px-2 py-1 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                <Button variant="outline" size="sm" onClick={() => { addIoc(iocText, "manual"); setIocText(""); }}>Add</Button>
              </div>
              {iocErr && <p className="mt-1 text-[10px] text-severity-high">{iocErr}</p>}
            </div>
            <input value={form.assessment} onChange={e => setForm(f => ({ ...f, assessment: e.target.value }))} placeholder="Assessment — what you think this is" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <div className="flex gap-2">
              <select value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">{SEVERITIES.map(s => <option key={s} value={s}>severity: {s}</option>)}</select>
              <select value={form.requested_action} onChange={e => setForm(f => ({ ...f, requested_action: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">{REQUESTED_ACTIONS.map(a => <option key={a} value={a}>action: {a}</option>)}</select>
            </div>
            {/* T1-6: live checklist for the hard gate — ✓/○ per item + positive "all set" */}
            <div className="text-[10px] leading-relaxed text-slate-500">
              {canEscalate ? (
                <span className="font-semibold text-neon-green">✓ all set — ready to escalate</span>
              ) : (
                <>Before escalating:{" "}
                  {([[gate.disposition, "disposition"], [gate.summary, "summary"], [gate.rationale, `observations (${rationaleWords}/${MIN_RATIONALE_WORDS} words)`], [gate.ioc, "≥1 IOC"], [gate.severity, "severity"]] as [boolean, string][]).map(([ok, label]) => (
                    <span key={label} className={ok ? "text-neon-green" : ""}>{ok ? "✓" : "○"} {label}&nbsp;&nbsp;</span>
                  ))}
                </>
              )}
            </div>
            <div className="flex gap-2 pt-1">
              <Button variant="outline" size="sm" className="flex-1" onClick={() => setReportOpen(false)}>Cancel</Button>
              <Button variant="primary" size="sm" className="flex-1" disabled={!canEscalate} onClick={escalate}><ArrowUpRight className="mr-1.5 h-4 w-4" /> Escalate to Tier-2</Button>
            </div>
          </div>
        </div>
      </div>
    )}
    </>
  );
}

// Shared working-scope shape (T2 sets, T3 confirms) — G-10.
type ScopeState = { hosts: string[]; users: string[]; techniques: string[]; confirmed: boolean; by: string | null } | null;

// ── T2/T3 console: escalation inbox → ack → request/execute containment + scope ─
const BOUNCE_REASONS = ["Missing a clear indicator", "Looks like noise / benign", "Needs more context or evidence", "Duplicate of another case", "Other"];
const T2_REPORT_VERDICTS = ["true_positive", "false_positive", "benign", "escalate"];
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0.5 };
const slaMinFor = (sev: string) => (sev === "critical" ? 1 : sev === "high" ? 3 : sev === "medium" ? 10 : 30);

function T2Console({ role, meId, escalations, acked, ackedBy, escBounced, escResolved, reportedIds, reportByEid, elevatedIds, contReq, contApproved, contExecuted, scope, nameOf, act, onEdr, onPivot }: {
  role: string; meId: string; escalations: Ev[]; acked: Set<string>; ackedBy: Map<string, string>; escBounced: Set<string>; escResolved: Set<string>; reportedIds: Set<string>; reportByEid: Map<string, { verdict?: string; findings?: string; recommendation?: string; summary?: string }>; elevatedIds: Set<string>; contReq: Ev[]; contApproved: Set<string>; contExecuted: Set<string>;
  scope: ScopeState; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onEdr?: (description?: string) => void;
  onPivot?: (field: "user" | "host" | "ip", value: string) => void;
}) {
  const [busy, setBusy] = useState<string | null>(null);
  const [openLog, setOpenLog] = useState<number | null>(null); // which escalation's full log is expanded
  const [bouncingId, setBouncingId] = useState<string | null>(null); // eid being bounced (shows reason input)
  const [bounceReason, setBounceReason] = useState(BOUNCE_REASONS[0]);
  const [bounceMsg, setBounceMsg] = useState("");
  const [reportFor, setReportFor] = useState<string | null>(null); // eid whose report form is open
  const [rep, setRep] = useState({ summary: "", findings: "", verdict: "true_positive", recommendation: "" });
  const [elevatingId, setElevatingId] = useState<string | null>(null); // A2: eid being elevated (shows the "what to hunt" compose)
  const [huntAsk, setHuntAsk] = useState("");
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null); // A3: live threat-intel enrichment
  // scope-first: containment can't be requested until a working scope exists.
  const scopeSet = !!scope && (scope.hosts.length > 0 || scope.users.length > 0 || scope.techniques.length > 0);
  async function submitReport(eid: string) {
    const words = rep.findings.trim().split(/\s+/).filter(Boolean).length;
    if (!rep.summary.trim() || words < 12 || !rep.recommendation.trim()) return;
    setBusy("rep" + eid);
    const ok = await act("report.submitted", { event_id: eid, summary: rep.summary.trim(), findings: rep.findings.trim(), verdict: rep.verdict, recommendation: rep.recommendation.trim() });
    setBusy(null);
    if (ok) { setReportFor(null); setRep({ summary: "", findings: "", verdict: "true_positive", recommendation: "" }); }
  }
  // For Tier-3 the inbox is secondary (hunting is the dominant action) → collapse it
  // by default so the console isn't a wall of always-open cards.
  const [inboxOpen, setInboxOpen] = useState(role !== "t3");
  // Approved but not yet executed → the analyst must carry out the isolation (G-09).
  const toExecute = contReq.filter(e => { const eid = String((e.payload as { event_id?: string }).event_id); return contApproved.has(eid) && !contExecuted.has(eid); });
  // Which escalations already have a containment request (so the button reflects it).
  const requestedIds = new Set(contReq.map(e => String((e.payload as { event_id?: string }).event_id)));
  // Prioritized queue: open cases first, ranked by severity × waiting × confidence
  // (a 'contain' request weighs heavier). Acked/bounced/resolved sink to the bottom.
  const now = Date.now();
  const prioKey = (e: Ev) => {
    const p = e.payload as { event_id?: string; severity?: string; confidence?: number; requested_action?: string };
    const eid = String(p.event_id);
    const open = !acked.has(eid) && !escBounced.has(eid) && !escResolved.has(eid);
    const sev = asStr(p.severity) || "medium";
    const wait = e.occurred_at ? Math.max(0, (now - Date.parse(e.occurred_at)) / 60000) : 0;
    const conf = typeof p.confidence === "number" ? p.confidence : 0.5;
    const contain = p.requested_action === "contain" ? 1.5 : 1;
    return { open, score: (SEV_RANK[sev] ?? 2) * (1 + wait / 5) * (0.5 + conf) * contain };
  };
  const prioritized = [...escalations].sort((a, b) => { const ka = prioKey(a), kb = prioKey(b); if (ka.open !== kb.open) return ka.open ? -1 : 1; return kb.score - ka.score; });
  // Cases this analyst has taken (acked, not resolved) — the ones a report can be
  // attached to in the bottom "your report" section (§5 handover to T3/Manager).
  const eidOf = (e: Ev) => String((e.payload as { event_id?: string }).event_id);
  const myCases = prioritized.filter(e => { const eid = eidOf(e); return acked.has(eid) && !escResolved.has(eid); });
  const selEid = (reportFor && myCases.some(e => eidOf(e) === reportFor)) ? reportFor : (myCases[0] ? eidOf(myCases[0]) : null);
  const selCase = myCases.find(e => eidOf(e) === selEid) || null;
  const selLabel = selCase ? (asStr((selCase.payload as { summary?: string; what?: string }).summary) || asStr((selCase.payload as { what?: string }).what)) : "";
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white">
            {role === "t3" && <button onClick={() => setInboxOpen(o => !o)} className="text-slate-400 hover:text-white"><ChevronDown className={`h-4 w-4 transition-transform ${inboxOpen ? "" : "-rotate-90"}`} /></button>}
            <Siren className="h-4 w-4 text-neon-amber" /> Escalations for you ({escalations.length})
          </h3>
          {onEdr && <Button variant="outline" size="sm" onClick={() => onEdr()}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>}
        </div>
        {!inboxOpen ? <p className="mt-2 text-[11px] text-slate-500">{escalations.length} case(s) waiting — expand to review. Your focus is hunting &amp; scope below.</p>
          : escalations.length === 0 ? <p className="mt-2 text-xs text-slate-400">Nothing escalated yet. Tier-1 sends cases here.</p> : (
          <div className="mt-2 space-y-2">
            {prioritized.map(e => {
              const p = e.payload as { event_id?: string; what?: string; summary?: string; why?: string; observations?: string; assessment?: string; impact?: string; severity?: string; confidence?: number; requested_action?: string; entity?: string; hostname?: string; low_confidence?: boolean; iocs?: Ioc[]; snapshot?: Record<string, unknown> };
              const eid = String(p.event_id); const isAck = acked.has(eid); const isBounced = escBounced.has(eid); const isResolved = escResolved.has(eid); const b = busy === e.seq + "";
              const target = asStr(p.entity) || asStr(p.hostname) || asStr(p.impact) || "the affected asset";
              const iocs = Array.isArray(p.iocs) ? p.iocs : [];
              const snap = enrichSnapshot(p.snapshot); const isOpen = openLog === e.seq;
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <div className="flex items-start gap-2">
                    <p className="min-w-0 flex-1 text-sm text-slate-200">{asStr(p.summary) || asStr(p.what)}</p>
                    {p.low_confidence && <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">low-conf</span>}
                    {isResolved ? <span className="shrink-0 rounded border border-neon-green/40 bg-neon-green/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-green">resolved</span>
                      : isBounced ? <span className="shrink-0 rounded border border-neon-amber/40 bg-neon-amber/10 px-1 py-0.5 text-[9px] font-bold uppercase text-neon-amber">bounced</span> : null}
                  </div>
                  {/* The ticket carries T1's initial investigation — the label makes the
                      bundle explicit (investigation + indicators + the log below). */}
                  {(asStr(p.observations) || asStr(p.why) || asStr(p.assessment)) && (
                    <div className="mt-1 rounded border border-border/50 bg-bg-elevated/30 px-2 py-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Tier-1 initial investigation</p>
                      <p className="mt-0.5 text-[11px] text-slate-300">{asStr(p.observations) || asStr(p.why)}</p>
                      {asStr(p.assessment) && <p className="mt-0.5 text-[11px] text-slate-400">Assessment: {asStr(p.assessment)}</p>}
                    </div>
                  )}
                  {iocs.length > 0 && (
                    <div className="mt-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Indicators ({iocs.length})</p>
                      <div className="mt-0.5 flex flex-wrap gap-1">{iocs.slice(0, 8).map(i => <span key={i.value} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[9px] text-slate-300"><span className="text-slate-500">{i.type}:</span>{i.value}</span>)}</div>
                    </div>
                  )}
                  <p className="mt-1 flex flex-wrap items-center gap-1.5 font-mono text-[10px] text-slate-500">
                    <span>from {nameOf(e.actor_id)} · sev {asStr(p.severity) || asStr(p.impact) || "—"} · conf {p.confidence}{p.requested_action ? ` · asks: ${p.requested_action}` : ""}</span>
                    {!isAck && !isBounced && !isResolved && e.occurred_at && (() => {
                      const mins = Math.floor((Date.now() - Date.parse(e.occurred_at)) / 60000);
                      const breached = mins >= slaMinFor(asStr(p.severity) || "medium"); // SLA by severity
                      return <span className={`rounded border px-1 py-px font-bold ${breached ? "border-severity-high/60 bg-severity-high/15 text-severity-high" : "border-border text-slate-400"}`}>⏱ waiting {mins}m{breached ? " · SLA" : ""}</span>;
                    })()}
                  </p>
                  {/* Open the FULL original log T1 flagged — investigate the real event, not just the words */}
                  {snap && (
                    <button onClick={() => setOpenLog(isOpen ? null : e.seq)} className="mt-1 flex items-center gap-1 text-[11px] text-cyber-300 underline-offset-2 hover:underline">
                      <ChevronDown className={`h-3.5 w-3.5 transition-transform ${isOpen ? "" : "-rotate-90"}`} /> {isOpen ? "Hide the log" : "View the full log (raw event + JSON)"}
                    </button>
                  )}
                  {snap && isOpen && (
                    <div className="mt-2 rounded-lg border border-border/60 bg-bg-elevated/40">
                      <DetailPanelBody event={snap} onThreatQuery={setThreatQuery} onPivot={onPivot} />
                    </div>
                  )}
                  {/* Routed handling: whoever acknowledges first has claimed the case;
                      a second Tier-2 sees the lock instead of double-handling it. */}
                  {isAck && (() => { const claimer = ackedBy.get(eid); return claimer && claimer !== meId
                    ? <p className="mt-1 text-[11px] text-neon-amber">🔒 handled by {nameOf(claimer)}</p>
                    : <p className="mt-1 text-[11px] text-neon-green">✓ you&apos;re handling this</p>; })()}
                  {/* EDR prompt — once taken, nudge the analyst to investigate on the endpoint
                      (both Tier-2 and Tier-3 can). Opens the EDR console with THIS event's
                      description in its header. Shown when the flagged log has endpoint context. */}
                  {isAck && (() => {
                    const so = p.snapshot as { source?: string; hostname?: string } | undefined;
                    const hasEndpoint = !!so && (so.source === "edr" || so.source === "sysmon" || !!so.hostname);
                    if (!hasEndpoint || !onEdr) return null;
                    return (
                      <div className="mt-2 flex items-center gap-2 rounded-lg border border-cyber-500/40 bg-cyber-500/[0.08] px-2.5 py-1.5">
                        <span className="text-sm leading-none">🖥</span>
                        <span className="min-w-0 flex-1 text-[11px] text-cyber-200">Endpoint activity on this host — investigate it in EDR before you decide.</span>
                        <Button variant="primary" size="sm" className="shrink-0" onClick={() => onEdr(asStr(p.summary) || asStr(p.what) || "Escalated incident")}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>
                      </div>
                    );
                  })()}
                  {!isResolved && (
                    <div className="mt-2 flex flex-wrap gap-1.5">
                      {!isAck && !isBounced
                        ? <Button variant="outline" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("escalation.acknowledged", { event_id: eid }); setBusy(null); }}><Check className="mr-1 h-3.5 w-3.5" /> Acknowledge (take this case)</Button>
                        : null}
                      {/* Report is a hard gate for containment + resolve (§5) */}
                      {isAck && !reportedIds.has(eid) && <Button variant="outline" size="sm" onClick={() => { setReportFor(eid); setRep({ summary: "", findings: "", verdict: "true_positive", recommendation: "" }); if (typeof document !== "undefined") document.getElementById("t2-report")?.scrollIntoView({ behavior: "smooth", block: "start" }); }}><FileText className="mr-1 h-3.5 w-3.5" /> Write report ↓</Button>}
                      {isAck && reportedIds.has(eid) && <span className="inline-flex items-center gap-1 text-[11px] text-neon-green"><CheckCircle2 className="h-3.5 w-3.5" /> report filed</span>}
                      {isAck && (requestedIds.has(eid)
                        ? <span className="inline-flex items-center gap-1 text-[11px] text-cyber-300"><ShieldAlert className="h-3.5 w-3.5" /> containment requested</span>
                        : <Button variant="primary" size="sm" disabled={b || !scopeSet || !reportedIds.has(eid)} onClick={async () => { setBusy(e.seq + ""); await act("containment.requested", { event_id: eid, target, reason: asStr(p.summary) || asStr(p.what) }); setBusy(null); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Request containment</Button>)}
                      {/* Escalate a hard case to Tier-3 for a deep hunt (routed handover, not shared) */}
                      {role === "t2" && isAck && (elevatedIds.has(eid)
                        ? <span className="inline-flex items-center gap-1 text-[11px] text-neon-purple"><ArrowUpRight className="h-3.5 w-3.5" /> escalated to Tier-3</span>
                        : elevatingId !== eid && <Button variant="outline" size="sm" disabled={b} onClick={() => { setElevatingId(eid); setHuntAsk(""); }}><ArrowUpRight className="mr-1 h-3.5 w-3.5" /> Escalate to Tier-3</Button>)}
                      {!isAck && !isBounced && bouncingId !== eid && <Button variant="outline" size="sm" disabled={b} onClick={() => { setBouncingId(eid); setBounceReason(BOUNCE_REASONS[0]); setBounceMsg(""); }}>Bounce</Button>}
                      {isAck && <Button variant="outline" size="sm" disabled={b || !reportedIds.has(eid)} onClick={async () => { setBusy(e.seq + ""); await act("escalation.resolved", { event_id: eid }); setBusy(null); }}>Resolve</Button>}
                      {/* Pin the key evidence to the Shared Case (wires the evidence.pinned rubric signal) */}
                      {isAck && <Button variant="outline" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("evidence.pinned", { event_id: eid, label: asStr(p.summary) || asStr(p.what) || "flagged log", iocs }); setBusy(null); }}>📌 Pin to case</Button>}
                    </div>
                  )}
                  {/* What's blocking containment/resolve on this ticket */}
                  {isAck && !isResolved && (!scopeSet || !reportedIds.has(eid)) && (
                    <p className="mt-1 text-[10px] text-slate-500">Before containment/resolve:{!reportedIds.has(eid) ? " write the incident report ·" : ""}{!scopeSet ? " set the scope (needed for containment)" : ""}</p>
                  )}
                  {/* Bounce from a preset reason list (+ optional detail) — real, specific feedback to T1 */}
                  {!isResolved && bouncingId === eid && (
                    <div className="mt-2 space-y-1.5">
                      <select value={bounceReason} onChange={ev => setBounceReason(ev.target.value)} className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">{BOUNCE_REASONS.map(r => <option key={r} value={r}>{r}</option>)}</select>
                      <div className="flex gap-1.5">
                        <input value={bounceMsg} onChange={ev => setBounceMsg(ev.target.value)} placeholder="Optional detail for Tier-1…" className="flex-1 rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                        <Button variant="outline" size="sm" disabled={b} onClick={async () => { const reason = bounceReason + (bounceMsg.trim() ? ` — ${bounceMsg.trim()}` : ""); setBusy(e.seq + ""); await act("escalation.bounced", { event_id: eid, reason }); setBusy(null); setBouncingId(null); }}>Send bounce</Button>
                        <Button variant="outline" size="sm" onClick={() => setBouncingId(null)}>✕</Button>
                      </div>
                    </div>
                  )}
                  {/* A2: elevate-to-Tier-3 compose — a required "what to hunt / why", and T2's filed
                      findings ride along so the hunter starts from context, not the raw alert. */}
                  {!isResolved && elevatingId === eid && (() => { const rpt = reportByEid.get(eid); return (
                    <div className="mt-2 space-y-1.5 rounded-lg border border-neon-purple/30 bg-neon-purple/[0.05] p-2">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">Hand off to Tier-3 — what should they hunt?</p>
                      <textarea value={huntAsk} onChange={ev => setHuntAsk(ev.target.value)} placeholder="What to hunt & why you're elevating (e.g. 'confirmed C2 beacon from WS-FIN-2847 — hunt lateral movement to the DC and check other finance hosts for the same hash')" rows={2} className="w-full resize-y rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                      {rpt ? <p className="text-[10px] text-neon-green">✓ your filed report (verdict + findings + recommendation) will travel with this elevation.</p>
                           : <p className="text-[10px] text-neon-amber">⚠ no report filed yet — Tier-3 gets more to work with if you write the report first.</p>}
                      <div className="flex gap-1.5">
                        <Button variant="primary" size="sm" disabled={b || huntAsk.trim().length < 8} onClick={async () => { setBusy(e.seq + ""); await act("elevation.requested", { event_id: eid, summary: asStr(p.summary) || asStr(p.what), snapshot: p.snapshot, hostname: asStr(p.hostname), entity: asStr(p.entity), severity: asStr(p.severity), iocs, hunt_ask: huntAsk.trim(), t2_verdict: rpt?.verdict, t2_findings: rpt?.findings, t2_recommendation: rpt?.recommendation }); setBusy(null); setElevatingId(null); }}><ArrowUpRight className="mr-1 h-3.5 w-3.5" /> Send to Tier-3</Button>
                        <Button variant="outline" size="sm" onClick={() => setElevatingId(null)}>✕</Button>
                      </div>
                    </div>
                  ); })()}
                </div>
              );
            })}
          </div>
        )}
      </Card>

      {/* G-09: Lead approved → execute the isolation (real MTTC starts at request, ends here) */}
      {toExecute.length > 0 && (
        <Card className="border-neon-green/30">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-neon-green" /> Approved — execute isolation ({toExecute.length})</h3>
          <div className="mt-2 space-y-2">
            {toExecute.map(e => {
              const p = e.payload as { event_id?: string; target?: string; reason?: string }; const eid = String(p.event_id); const b = busy === "x" + e.seq;
              return (
                <div key={e.seq} className="flex items-center gap-2 rounded-lg border border-border bg-bg px-3 py-2">
                  <span className="min-w-0 flex-1 truncate text-sm text-slate-200">Isolate <b className="text-white">{asStr(p.target) || "host"}</b></span>
                  <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy("x" + e.seq); await act("containment.executed", { event_id: eid, target: p.target }); setBusy(null); }}><ShieldAlert className="mr-1 h-3.5 w-3.5" /> Execute</Button>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* T2 sets the scope here; T3 gets the confirm-scope panel in its Hunt console
          instead (avoids showing two scope panels to Tier-3). */}
      {role === "t2" && <ScopeConsole scope={scope} mode="set" act={act} />}

      {/* ── Bottom of the page: the analyst's own report ── §5 handover. A dedicated
          place (not buried in a ticket) to attach the report, the determination and
          the recommendations. Filing it is what unlocks containment & resolve. */}
      <Card className="border-cyber-500/30">
        <div id="t2-report" className="scroll-mt-4" />
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FileText className="h-4 w-4 text-cyber-300" /> Your incident report — determination &amp; recommendations</h3>
        <p className="mt-0.5 text-[11px] text-slate-400">Attach your report to a case you&apos;ve taken. This is the handover Tier-3 and the SOC Manager read: your findings, your determination (verdict), and what you recommend next. Filing it unlocks <b className="text-slate-300">containment</b> and <b className="text-slate-300">resolve</b> on that case.</p>
        {myCases.length === 0 ? (
          <p className="mt-2 text-xs text-slate-400">Acknowledge a case in the inbox above, then write its report here.</p>
        ) : (
          <div className="mt-3 space-y-2">
            {/* Which case is this report for */}
            <div>
              <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Case this report is for</label>
              <select value={selEid ?? ""} onChange={ev => { setReportFor(ev.target.value); setRep({ summary: "", findings: "", verdict: "true_positive", recommendation: "" }); }} className="mt-1 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:border-cyber-500/50 focus:outline-none">
                {myCases.map(e => { const eid = eidOf(e); const p = e.payload as { summary?: string; what?: string }; return <option key={eid} value={eid}>{reportedIds.has(eid) ? "✓ " : ""}{asStr(p.summary) || asStr(p.what) || eid}</option>; })}
              </select>
            </div>
            {selEid && reportedIds.has(selEid) ? (
              <div className="flex items-start gap-2 rounded-lg border border-neon-green/30 bg-neon-green/[0.06] px-3 py-2 text-[11px] text-neon-green"><CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /><span>Report filed for <b>{selLabel}</b>. Containment &amp; resolve are unlocked for this case. Pick another case above to report it, or resolve this one in the inbox.</span></div>
            ) : selEid ? (
              <div className="space-y-1.5 rounded-lg border border-cyber-500/30 bg-cyber-500/[0.05] p-3">
                <p className="text-[10px] text-slate-400">Reporting on: <b className="text-slate-200">{selLabel}</b></p>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Summary — what this incident is</label>
                  <input value={rep.summary} onChange={ev => setRep(s => ({ ...s, summary: ev.target.value }))} placeholder="e.g. Malicious macro on WS-FIN-2847 dropped an encoded PowerShell C2 beacon" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Findings — what you investigated, the evidence, the scope (≥ 12 words)</label>
                  <textarea value={rep.findings} onChange={ev => setRep(s => ({ ...s, findings: ev.target.value }))} placeholder="What you confirmed in the log/EDR, the indicators, the affected hosts/users, whether it spread…" rows={3} className="mt-1 w-full resize-y rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Determination (verdict)</label>
                  <select value={rep.verdict} onChange={ev => setRep(s => ({ ...s, verdict: ev.target.value }))} className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 focus:border-cyber-500/50 focus:outline-none">{T2_REPORT_VERDICTS.map(v => <option key={v} value={v}>{v.replace("_", " ")}</option>)}</select>
                </div>
                <div>
                  <label className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Recommendations — what should happen next</label>
                  <input value={rep.recommendation} onChange={ev => setRep(s => ({ ...s, recommendation: ev.target.value }))} placeholder="e.g. Isolate the host, block the domain, reset the user, hunt the hash fleet-wide" className="mt-1 w-full rounded border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                </div>
                <div className="flex items-center gap-2 pt-0.5">
                  <Button variant="primary" size="sm" disabled={busy === "rep" + selEid || !rep.summary.trim() || rep.findings.trim().split(/\s+/).filter(Boolean).length < 12 || !rep.recommendation.trim()} onClick={() => submitReport(selEid)}><FileText className="mr-1 h-3.5 w-3.5" /> File report</Button>
                  <span className="text-[10px] text-slate-500">{rep.findings.trim().split(/\s+/).filter(Boolean).length}/12 words in findings</span>
                </div>
              </div>
            ) : null}
          </div>
        )}
      </Card>
      {/* A3: live threat-intel enrichment when a hash/IP/domain is checked in a log */}
      {threatQuery && <ThreatIntelDrawer key="t2-threat" query={threatQuery} onClose={() => setThreatQuery(null)} />}
    </div>
  );
}

// ── Scope console (G-10): T2 proposes scope, T3 confirms/amends ───────────────
function ScopeConsole({ scope, mode, act }: { scope: ScopeState; mode: "set" | "confirm"; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [hosts, setHosts] = useState(scope?.hosts.join(", ") ?? "");
  const [users, setUsers] = useState(scope?.users.join(", ") ?? "");
  const [techs, setTechs] = useState(scope?.techniques.join(", ") ?? "");
  const [busy, setBusy] = useState(false);
  // Re-sync the fields when the shared scope actually changes (e.g. T2 amends it
  // after T3's console already mounted) so T3 confirms the LATEST proposal, not a
  // stale one. Keyed on the scope's content signature so typing isn't clobbered.
  const scopeSig = scope ? `${scope.hosts.join()}|${scope.users.join()}|${scope.techniques.join()}|${scope.confirmed}` : "";
  useEffect(() => {
    setHosts(scope?.hosts.join(", ") ?? "");
    setUsers(scope?.users.join(", ") ?? "");
    setTechs(scope?.techniques.join(", ") ?? "");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scopeSig]);
  const parse = (s: string) => s.split(",").map(x => x.trim()).filter(Boolean);
  async function submit(type: "scope.set" | "scope.confirmed") {
    setBusy(true);
    const ok = await act(type, { hosts: parse(hosts), users: parse(users), techniques: parse(techs) });
    setBusy(false);
    if (ok && type === "scope.confirmed") { /* confirmed — leave fields as the locked value */ }
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Incident scope</h3>
      <p className="mt-0.5 text-[11px] text-slate-400">{mode === "set" ? "Define what's in play — hosts, users, techniques. Tier-3 confirms it." : "Review Tier-2's scope, amend if needed, then confirm the final scope."}</p>
      {scope && <p className="mt-1 text-[10px] font-mono text-slate-500">current: {scope.hosts.length}h · {scope.users.length}u · {scope.techniques.length}t {scope.confirmed ? "· ✓ confirmed" : "· proposed"}</p>}
      <div className="mt-2 space-y-1.5">
        <input value={hosts} onChange={e => setHosts(e.target.value)} placeholder="hosts (comma-separated)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={users} onChange={e => setUsers(e.target.value)} placeholder="users" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={techs} onChange={e => setTechs(e.target.value)} placeholder="techniques (T1234…)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
      </div>
      <div className="mt-2 flex gap-1.5">
        <Button variant="outline" size="sm" disabled={busy} onClick={() => submit("scope.set")}>{mode === "set" ? "Set scope" : "Amend"}</Button>
        {mode === "confirm" && <Button variant="primary" size="sm" disabled={busy} onClick={() => submit("scope.confirmed")}><CheckCircle2 className="mr-1 h-3.5 w-3.5" /> Confirm scope</Button>}
      </div>
    </Card>
  );
}

// ── Lead console: containment requests → approve / deny ──────────────────────
function LeadConsole({ contReq, contDecided, escalations, acked, events, nameOf, act }: { contReq: Ev[]; contDecided: Set<string>; escalations: Ev[]; acked: Set<string>; events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({}); // per-request decision rationale
  const pending = contReq.filter(e => !contDecided.has(String((e.payload as { event_id?: string }).event_id)));
  const escResolvedSet = useMemo(() => new Set(events.filter(e => e.type === "escalation.resolved").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  // A1: T2's determination/recommendation per case + the working scope, so the
  // Manager approves containment WITH the justification, not blind.
  const reportByEid = useMemo(() => { const m = new Map<string, { verdict?: string; recommendation?: string; findings?: string; summary?: string }>(); for (const e of events) if (e.type === "report.submitted") m.set(String((e.payload as { event_id?: string }).event_id), e.payload as { verdict?: string; recommendation?: string; findings?: string; summary?: string }); return m; }, [events]);
  const latestScope = useMemo(() => { const s = [...events].reverse().find(e => e.type === "scope.set" || e.type === "scope.confirmed"); return s ? (s.payload as { hosts?: string[]; users?: string[]; techniques?: string[] }) : null; }, [events]);
  // Oversight queue: escalations still waiting for a Tier-2 to pick up (unacked,
  // unresolved) — so the Manager sees the backlog from the first minute and can
  // chase it, instead of only getting work once a containment request lands.
  const waiting = escalations
    .filter(e => { const eid = String((e.payload as { event_id?: string }).event_id); return !acked.has(eid) && !escResolvedSet.has(eid); })
    .map(e => { const p = e.payload as { event_id?: string; summary?: string; what?: string; severity?: string }; const mins = e.occurred_at ? Math.floor((Date.now() - Date.parse(e.occurred_at)) / 60000) : 0; return { seq: e.seq, label: asStr(p.summary) || asStr(p.what) || "escalation", sev: asStr(p.severity), mins }; })
    .sort((a, b) => b.mins - a.mins);
  return (
    <div className="space-y-4">
      {/* Manager oversight — the queue state at a glance (no raw feed) */}
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Queue oversight</h3>
        {waiting.length === 0 ? (
          <p className="mt-2 text-xs text-slate-400">No escalations waiting to be picked up. Tier-2 is on top of the queue.</p>
        ) : (
          <>
            <p className="mt-1 text-[11px] text-slate-400">{waiting.length} escalation{waiting.length !== 1 ? "s" : ""} not yet picked up by Tier-2 — chase the oldest / highest-severity first.</p>
            <div className="mt-2 space-y-1">
              {waiting.slice(0, 6).map(w => (
                <div key={w.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1 text-[11px]">
                  <span className="min-w-0 flex-1 truncate text-slate-300">{w.label}</span>
                  {w.sev && <span className="shrink-0 rounded border border-border px-1 py-0.5 font-mono text-[9px] uppercase text-slate-400">{w.sev}</span>}
                  <span className={`shrink-0 rounded border px-1 py-0.5 font-mono text-[9px] font-bold ${(w.sev === "high" || w.sev === "critical") && w.mins >= 5 ? "border-neon-amber/50 bg-neon-amber/10 text-neon-amber" : "border-border text-slate-400"}`}>⏱ {w.mins}m</span>
                </div>
              ))}
            </div>
          </>
        )}
      </Card>
      <Card className="border-neon-amber/30">
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-neon-amber" /> Containment approvals ({pending.length})</h3>
        {pending.length === 0 ? <p className="mt-2 text-xs text-slate-400">No requests waiting. Tier-2 asks you to approve containment here.</p> : (
          <div className="mt-2 space-y-2">
            {pending.map(e => {
              const p = e.payload as { event_id?: string; target?: string; reason?: string }; const eid = String(p.event_id); const b = busy === e.seq + "";
              const note = notes[eid] ?? "";
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <p className="text-sm text-slate-200">Contain <b className="text-white">{p.target}</b></p>
                  <p className="mt-0.5 text-[11px] text-slate-400">{p.reason} · requested by {nameOf(e.actor_id)}</p>
                  {/* A1: T2's determination + recommendation + scope, so this isn't a blind approval */}
                  {(() => { const r = reportByEid.get(eid); return r ? (
                    <div className="mt-1.5 rounded border border-cyber-500/25 bg-cyber-500/[0.05] px-2 py-1.5 text-[11px]">
                      <p className="text-slate-300"><span className="font-semibold text-cyber-200">T2 determination:</span> {asStr(r.verdict).replace("_", " ") || "—"}</p>
                      {asStr(r.recommendation) && <p className="mt-0.5 text-slate-300"><span className="text-slate-500">recommends:</span> {asStr(r.recommendation)}</p>}
                      {latestScope && <p className="mt-0.5 font-mono text-[10px] text-slate-500">scope: {(latestScope.hosts ?? []).length}h · {(latestScope.users ?? []).length}u · {(latestScope.techniques ?? []).length}t{latestScope.hosts?.length ? ` — ${latestScope.hosts.join(", ")}` : ""}</p>}
                    </div>
                  ) : <p className="mt-1 text-[10px] text-neon-amber">⚠ No incident report filed for this case yet — ask Tier-2 to file it before you approve.</p>; })()}
                  {/* Decision rationale — optional to Approve (fast confident call), required to Deny */}
                  <input value={note} onChange={ev => setNotes(n => ({ ...n, [eid]: ev.target.value }))} placeholder="Decision rationale — business impact / why (required to deny)" className="mt-2 w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
                  <div className="mt-2 flex gap-1.5">
                    <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("containment.approved", { event_id: eid, reason: note.trim() || undefined }); setBusy(null); }}><Check className="mr-1 h-3.5 w-3.5" /> Approve</Button>
                    <Button variant="outline" size="sm" disabled={b || !note.trim()} onClick={async () => { setBusy(e.seq + ""); await act("containment.denied", { event_id: eid, reason: note.trim() }); setBusy(null); }}>Deny</Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Card>
      {/* G-15: Decision Log — the Lead records key decisions with rationale (feeds the AAR + rubric) */}
      <DecisionLog events={events} nameOf={nameOf} act={act} />
      {/* G-15 tail: SITREP — the 4-question situation report to the team/management */}
      <SitrepConsole events={events} nameOf={nameOf} act={act} />
    </div>
  );
}

// ── G-15: SITREP (Lead) — a 4-question situation report ───────────────────────
function SitrepConsole({ events, nameOf, act }: { events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ situation: "", actions: "", status: "", next: "" });
  const [busy, setBusy] = useState(false);
  const sitreps = events.filter(e => e.type === "sitrep.sent");
  // Quality gate (parity with T1's escalation gate): a real SITREP answers all four
  // questions, with a substantive situation line (≥8 words), not one-word fields.
  const canSend = wordCount(f.situation) >= 8 && !!f.actions.trim() && !!f.status.trim() && !!f.next.trim();
  async function send() {
    if (!canSend) return;
    setBusy(true); const ok = await act("sitrep.sent", { situation: f.situation.trim(), actions: f.actions.trim(), status: f.status.trim(), next: f.next.trim() }); setBusy(false);
    if (ok) setF({ situation: "", actions: "", status: "", next: "" });
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-cyber-300" /> SITREP ({sitreps.length})</h3>
      {sitreps.length > 0 && (
        <div className="mt-2 max-h-40 space-y-1 overflow-y-auto">
          {sitreps.slice().reverse().map(e => { const p = e.payload as { situation?: string; status?: string }; return (
            <div key={e.seq} className="rounded border border-border/60 bg-bg px-2 py-1 text-xs">
              <p className="text-slate-200">{asStr(p.situation)}</p>
              <p className="text-[10px] text-slate-500">status: {asStr(p.status)} · {nameOf(e.actor_id)}</p>
            </div>
          ); })}
        </div>
      )}
      <div className="mt-2 space-y-1.5">
        <input value={f.situation} onChange={e => setF(s => ({ ...s, situation: e.target.value }))} placeholder="1. What's happening?" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={f.actions} onChange={e => setF(s => ({ ...s, actions: e.target.value }))} placeholder="2. Actions taken" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={f.status} onChange={e => setF(s => ({ ...s, status: e.target.value }))} placeholder="3. Current status" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={f.next} onChange={e => setF(s => ({ ...s, next: e.target.value }))} placeholder="4. Next steps" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        {!canSend && <p className="text-[10px] text-slate-500">Answer all four — situation needs ≥ 8 words.</p>}
        <Button variant="outline" size="sm" disabled={busy || !canSend} onClick={send}>Send SITREP</Button>
      </div>
    </Card>
  );
}

// ── G-15: Decision Log (Lead/Mgr) — decision.logged is already gated ──────────
function DecisionLog({ events, nameOf, act }: { events: Ev[]; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ decision: "", rationale: "" });
  const [busy, setBusy] = useState(false);
  const decisions = events.filter(e => e.type === "decision.logged");
  // Quality gate: a decision without a substantive rationale (≥8 words) is what an
  // IR reviewer flags first — require the "why", matching T1's escalation discipline.
  const canLog = f.decision.trim().length >= 5 && wordCount(f.rationale) >= 8;
  async function log() {
    if (!canLog) return;
    setBusy(true); const ok = await act("decision.logged", { decision: f.decision.trim(), rationale: f.rationale.trim() }); setBusy(false);
    if (ok) setF({ decision: "", rationale: "" });
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Check className="h-4 w-4 text-cyber-300" /> Decision log ({decisions.length})</h3>
      {decisions.length > 0 && (
        <div className="mt-2 max-h-40 space-y-1 overflow-y-auto">
          {decisions.slice().reverse().map(e => { const p = e.payload as { decision?: string; rationale?: string }; return (
            <div key={e.seq} className="rounded border border-border/60 bg-bg px-2 py-1 text-xs">
              <p className="text-slate-200">{asStr(p.decision)}</p>
              {asStr(p.rationale) && <p className="text-[10px] text-slate-500">why: {asStr(p.rationale)} · {nameOf(e.actor_id)}</p>}
            </div>
          ); })}
        </div>
      )}
      <div className="mt-2 space-y-1.5">
        <input value={f.decision} onChange={e => setF(s => ({ ...s, decision: e.target.value }))} placeholder="Decision (e.g. 'isolate FIN-WS-07, keep DC online')" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <textarea value={f.rationale} onChange={e => setF(s => ({ ...s, rationale: e.target.value }))} placeholder="Rationale — why this call, and the business impact considered (≥ 8 words)" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        {!canLog && <p className="text-[10px] text-slate-500">Needs: a decision + a rationale of at least 8 words.</p>}
        <Button variant="outline" size="sm" disabled={busy || !canLog} onClick={log}>Log decision</Button>
      </div>
    </Card>
  );
}

// Add a member to a live/lobby session (staff) — grow the team or backfill a
// role. Calls the /members route; the invitee then sees it under Team training.
function AddMemberPanel({ sessionId, roster }: { sessionId: string; roster: RosterMember[] }) {
  const [members, setMembers] = useState<{ user_id: string; display_name: string | null; handle: string | null; status: string }[]>([]);
  const [pick, setPick] = useState({ user_id: "", role: "t1" });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open || members.length) return;
    (async () => {
      const res = await fetch("/api/org/members");
      if (!res.ok) return;
      const data = await res.json();
      setMembers((data.members ?? []).filter((m: { status: string }) => m.status === "active"));
    })();
  }, [open, members.length]);
  const inSession = new Set(roster.map(r => r.user_id));
  const available = members.filter(m => !inSession.has(m.user_id));
  async function add() {
    if (!pick.user_id) return;
    setBusy(true); setMsg(null);
    try {
      const res = await fetch(`/api/team/sessions/${sessionId}/members`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(pick) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? "Could not add the member.");
      const who = members.find(m => m.user_id === pick.user_id);
      setMsg({ ok: true, text: `${who?.display_name || who?.handle || "Member"} added as ${ROLE_LABEL[pick.role] ?? pick.role}. They'll see it under Team training.` });
      setPick({ user_id: "", role: "t1" });
    } catch (e) { setMsg({ ok: false, text: e instanceof Error ? e.message : "Could not add the member." }); }
    finally { setBusy(false); }
  }
  return (
    <div className="mt-3 border-t border-border/50 pt-3">
      {!open ? (
        <button onClick={() => setOpen(true)} className="inline-flex items-center gap-1 text-[11px] font-semibold text-cyber-300 hover:underline"><UserPlus className="h-3.5 w-3.5" /> Add a member</button>
      ) : (
        <div className="space-y-1.5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Add a member</p>
          <div className="flex gap-1.5">
            <select value={pick.user_id} onChange={e => setPick(s => ({ ...s, user_id: e.target.value }))} className="min-w-0 flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
              <option value="">— member —</option>
              {available.map(m => <option key={m.user_id} value={m.user_id}>{m.display_name || m.handle || m.user_id.slice(0, 8)}</option>)}
            </select>
            <select value={pick.role} onChange={e => setPick(s => ({ ...s, role: e.target.value }))} className="rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
              {["t1", "t2", "t3", "mgr", "observer"].map(r => <option key={r} value={r}>{ROLE_LABEL[r] ?? r}</option>)}
            </select>
            <Button variant="outline" size="sm" disabled={busy || !pick.user_id} onClick={add}>Add</Button>
          </div>
          {available.length === 0 && members.length > 0 && <p className="text-[11px] text-slate-500">Everyone active is already on the roster.</p>}
          {msg && <p className={`text-[11px] ${msg.ok ? "text-neon-green" : "text-severity-high"}`}>{msg.text}</p>}
        </div>
      )}
    </div>
  );
}

function InstructorPanel({ sessionId, roster, online, events, act }: { sessionId: string; roster: RosterMember[]; online: Set<string>; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  // G-14: inject-composer — the instructor injects an announcement or a help-desk
  // ticket mid-exercise (staff.inject). Tickets land in Tier-1's queue to answer.
  const [inj, setInj] = useState({ kind: "announcement", text: "" });
  const [busy, setBusy] = useState(false);
  const injects = events.filter(e => e.type === "staff.inject");
  // F7: recover a dropped single-seat by handing the role to another member.
  const [ra, setRa] = useState({ user_id: "", role: "" });
  const [raBusy, setRaBusy] = useState(false);
  const [raMsg, setRaMsg] = useState<{ ok: boolean; text: string } | null>(null);
  async function reassign() {
    if (!ra.user_id || !ra.role) return;
    setRaBusy(true); setRaMsg(null);
    try {
      const res = await fetch(`/api/team/sessions/${sessionId}/reassign`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ra),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error ?? "Reassign failed.");
      const who = roster.find(r => r.user_id === ra.user_id)?.name ?? "member";
      setRaMsg({ ok: true, text: `${who} → ${ROLE_LABEL[ra.role] ?? ra.role}. Ask them to refresh.` });
      setRa({ user_id: "", role: "" });
    } catch (e) {
      setRaMsg({ ok: false, text: e instanceof Error ? e.message : "Reassign failed." });
    } finally {
      setRaBusy(false);
    }
  }
  async function post() {
    if (inj.text.trim().length < 3) return;
    setBusy(true); const ok = await act("staff.inject", { kind: inj.kind, text: inj.text.trim() }); setBusy(false);
    if (ok) setInj({ kind: inj.kind, text: "" });
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-cyber-300" /> Instructor view</h3>
      <div className="mt-2 space-y-1">
        {roster.filter(r => r.role !== "instructor").map(m => (
          <div key={m.user_id} className="flex items-center gap-2 text-xs">
            <span className={`h-1.5 w-1.5 rounded-full ${online.has(m.user_id) ? "bg-neon-green" : "bg-slate-600"}`} />
            <span className="text-slate-300">{m.name}</span>
            <span className="font-mono text-[10px] text-slate-500">{ROLE_LABEL[m.role] ?? m.role}</span>
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Inject ({injects.length} sent)</p>
        <select value={inj.kind} onChange={e => setInj(s => ({ ...s, kind: e.target.value }))} className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
          <option value="announcement">announcement (all roles)</option>
          <option value="ticket">help-desk ticket (Tier-1 answers)</option>
          <option value="mgmt_pressure">management pressure (Manager)</option>
        </select>
        <textarea value={inj.text} onChange={e => setInj(s => ({ ...s, text: e.target.value }))} placeholder="Inject text (e.g. 'User in Finance says a vendor called asking for an MFA code')" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <Button variant="primary" size="sm" disabled={busy || inj.text.trim().length < 3} onClick={post}>Send inject</Button>
      </div>

      {/* F7: reassign a role — recover a dropped Tier-3 / Manager so the relay continues */}
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Reassign a role (recover a dropped seat)</p>
        <div className="flex gap-1.5">
          <select value={ra.user_id} onChange={e => setRa(s => ({ ...s, user_id: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
            <option value="">— member —</option>
            {roster.filter(r => r.role !== "instructor").map(m => <option key={m.user_id} value={m.user_id}>{m.name}{online.has(m.user_id) ? "" : " (offline)"}</option>)}
          </select>
          <select value={ra.role} onChange={e => setRa(s => ({ ...s, role: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none">
            <option value="">— role —</option>
            {["t1", "t2", "t3", "mgr"].map(r => <option key={r} value={r}>{ROLE_LABEL[r] ?? r}</option>)}
          </select>
        </div>
        <Button variant="outline" size="sm" disabled={raBusy || !ra.user_id || !ra.role} onClick={reassign}>Reassign</Button>
        {raMsg && <p className={`text-[11px] ${raMsg.ok ? "text-neon-green" : "text-severity-high"}`}>{raMsg.text}</p>}
      </div>

      {/* Grow the team mid-shift — add a member to a role */}
      <AddMemberPanel sessionId={sessionId} roster={roster} />
    </Card>
  );
}

// ── G-14: injects/announcements banner (everyone) + help-desk tickets (Tier-1) ─
function InjectFeed({ events, me, nameOf, act }: { events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [busy, setBusy] = useState<string | null>(null);
  const injects = events.filter(e => e.type === "staff.inject");
  if (injects.length === 0) return null;
  const answered = new Set(events.filter(e => e.type === "ticket.answered").map(e => String((e.payload as { ticket_seq?: number }).ticket_seq)));
  const isT1 = me.role === "t1";
  return (
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Injects & help-desk</h3>
      <div className="mt-2 space-y-1.5">
        {injects.slice().reverse().map(e => {
          const p = e.payload as { kind?: string; text?: string }; const kind = asStr(p.kind) || "announcement";
          const isTicket = kind === "ticket"; const done = answered.has(String(e.seq)); const b = busy === e.seq + "";
          return (
            <div key={e.seq} className={`rounded-lg border px-2 py-1.5 text-xs ${isTicket ? "border-neon-amber/30 bg-neon-amber/[0.05]" : "border-border bg-bg"}`}>
              <p className="text-slate-200"><span className="mr-1 font-mono text-[9px] uppercase text-slate-500">{kind.replace("_", " ")}</span>{asStr(p.text)}</p>
              {isTicket && isT1 && !done && (
                <div className="mt-1.5 flex gap-1.5">
                  <Button variant="primary" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("ticket.answered", { ticket_seq: e.seq, decision: "handled", response: "verified caller, no code shared" }); setBusy(null); }}>Handle</Button>
                  <Button variant="outline" size="sm" disabled={b} onClick={async () => { setBusy(e.seq + ""); await act("ticket.answered", { ticket_seq: e.seq, decision: "rejected", response: "refused the request and escalated to security" }); setBusy(null); }}>Refuse &amp; escalate to security</Button>
                </div>
              )}
              {isTicket && done && <p className="mt-0.5 text-[10px] text-neon-green">✓ answered by Tier-1</p>}
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ── T3 threat-hunt console ───────────────────────────────────────────────────
function HuntConsole({ scope, elevations, elevAcked, nameOf, act, onEdr, onPivot }: {
  scope: ScopeState; elevations: Ev[]; elevAcked: Set<string>; nameOf: (u: string | null) => string;
  act: (t: string, p: Record<string, unknown>) => Promise<boolean>; onEdr?: (description?: string) => void;
  onPivot?: (field: "user" | "host" | "ip", value: string) => void;
}) {
  const [f, setF] = useState({ hypothesis: "", finding: "", technique: "" });
  const [busy, setBusy] = useState(false);
  const [busyElev, setBusyElev] = useState<string | null>(null);
  const [openElev, setOpenElev] = useState<number | null>(null);
  const [threatQuery, setThreatQuery] = useState<ThreatQuery | null>(null); // A3: live threat-intel enrichment
  async function log() {
    if (f.hypothesis.trim().length < 8) return;
    setBusy(true); const ok = await act("hunt.logged", { ...f }); setBusy(false);
    if (ok) setF({ hypothesis: "", finding: "", technique: "" });
  }
  return (
    <div className="space-y-4">
      {/* Routed work handed down from Tier-2 — deep-hunt these specifically */}
      {elevations.length > 0 && (
        <Card className="border-neon-amber/30">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-neon-amber" /> Elevations for you ({elevations.length})</h3>
          <p className="mt-1 text-[11px] text-slate-400">Tier-2 handed these down for a deep hunt.</p>
          <div className="mt-2 space-y-2">
            {elevations.slice().reverse().map(e => {
              const p = e.payload as { event_id?: string; summary?: string; severity?: string; hostname?: string; entity?: string; snapshot?: Record<string, unknown>; hunt_ask?: string; t2_verdict?: string; t2_findings?: string; t2_recommendation?: string };
              const eid = String(p.event_id); const b = busyElev === e.seq + ""; const snap = enrichSnapshot(p.snapshot); const isOpen = openElev === e.seq;
              const done = elevAcked.has(eid);
              return (
                <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2">
                  <p className="text-sm text-slate-200">{asStr(p.summary) || "elevated case"}</p>
                  <p className="mt-0.5 font-mono text-[10px] text-slate-500">from {nameOf(e.actor_id)} · sev {asStr(p.severity) || "—"}{asStr(p.hostname) ? ` · ${asStr(p.hostname)}` : ""}</p>
                  {/* A2: the T2 hunt-ask + filed findings so the hunter starts from context, not the raw alert */}
                  {asStr(p.hunt_ask) && (
                    <div className="mt-1.5 rounded border border-neon-purple/30 bg-neon-purple/[0.06] px-2 py-1">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-neon-purple">Tier-2 asks you to hunt</p>
                      <p className="mt-0.5 text-[11px] text-slate-200">{asStr(p.hunt_ask)}</p>
                    </div>
                  )}
                  {(asStr(p.t2_findings) || asStr(p.t2_verdict) || asStr(p.t2_recommendation)) && (
                    <div className="mt-1 rounded border border-border/50 bg-bg-elevated/30 px-2 py-1 text-[11px]">
                      <p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Tier-2 investigation</p>
                      {asStr(p.t2_verdict) && <p className="mt-0.5 text-slate-400">verdict: {asStr(p.t2_verdict).replace("_", " ")}</p>}
                      {asStr(p.t2_findings) && <p className="mt-0.5 text-slate-300">{asStr(p.t2_findings)}</p>}
                      {asStr(p.t2_recommendation) && <p className="mt-0.5 text-cyber-200">▶ recommended: {asStr(p.t2_recommendation)}</p>}
                    </div>
                  )}
                  {snap && (
                    <button onClick={() => setOpenElev(isOpen ? null : e.seq)} className="mt-1 flex items-center gap-1 text-[11px] text-cyber-300 underline-offset-2 hover:underline">
                      <ChevronDown className={`h-3.5 w-3.5 transition-transform ${isOpen ? "" : "-rotate-90"}`} /> {isOpen ? "Hide the log" : "View the full log (raw event + JSON)"}
                    </button>
                  )}
                  {snap && isOpen && <div className="mt-2 rounded-lg border border-border/60 bg-bg-elevated/40"><DetailPanelBody event={snap} onThreatQuery={setThreatQuery} onPivot={onPivot} /></div>}
                  {!done && <Button variant="outline" size="sm" className="mt-2" disabled={b} onClick={async () => { setBusyElev(e.seq + ""); await act("elevation.acknowledged", { event_id: eid }); setBusyElev(null); }}><Check className="mr-1 h-3.5 w-3.5" /> Take the hunt</Button>}
                  {done && <p className="mt-1 text-[11px] text-neon-green">✓ taken — record findings below</p>}
                </div>
              );
            })}
          </div>
        </Card>
      )}
      <Card>
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Threat hunt (Tier-3)</h3>
          {onEdr && <Button variant="outline" size="sm" onClick={() => onEdr()}><Search className="mr-1 h-3.5 w-3.5" /> Investigate in EDR</Button>}
        </div>
        <p className="mt-1 text-[11px] text-slate-400">Beyond the queue: form a hypothesis, hunt the feed, record what you found.</p>
        <div className="mt-2 space-y-2">
          <input value={f.hypothesis} onChange={e => setF(s => ({ ...s, hypothesis: e.target.value }))} placeholder="Hypothesis (e.g. 'lateral movement from FIN-WS-07 via SMB')" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <textarea value={f.finding} onChange={e => setF(s => ({ ...s, finding: e.target.value }))} placeholder="Finding / evidence" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.technique} onChange={e => setF(s => ({ ...s, technique: e.target.value }))} placeholder="MITRE technique (optional, e.g. T1021.002)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <Button variant="primary" size="sm" disabled={busy || f.hypothesis.trim().length < 8} onClick={log}>Log hunt finding</Button>
        </div>
      </Card>
      {/* G-10: Tier-3 owns the FINAL scope — confirm or amend what Tier-2 proposed */}
      <ScopeConsole scope={scope} mode="confirm" act={act} />
      {/* A3: live threat-intel enrichment when a hash/IP/domain is checked in a log */}
      {threatQuery && <ThreatIntelDrawer key="t3-threat" query={threatQuery} onClose={() => setThreatQuery(null)} />}
    </div>
  );
}

// ── Detection Engineer console — G-06: predicate / KQL-lite back-test ─────────
function DEConsole({ liveFeed, events, act }: { liveFeed: LiveEvent[]; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ name: "", keyword: "", technique: "" });
  const [busy, setBusy] = useState(false);
  // Field-based back-test: `field:value` tokens AND-ed (source:edr mitre:T1059 …),
  // reusing the real feed search engine — not a naive substring. Falls back to
  // substring for bare terms, so simple queries still work.
  const matched = useMemo(() => {
    const q = f.keyword.trim();
    if (!q) return [] as LiveEvent[];
    return liveFeed.filter(e => eventMatchesSearch(e, q));
  }, [liveFeed, f.keyword]);
  const published = events.filter(e => e.type === "rule.published");
  const tuned = events.filter(e => e.type === "rule.tuned");
  const [tuneText, setTuneText] = useState("");
  const [busyTune, setBusyTune] = useState(false);
  async function publish() {
    if (!f.name.trim() || !f.keyword.trim()) return;
    setBusy(true); const ok = await act("rule.published", { ...f, matched: matched.length }); setBusy(false);
    if (ok) setF({ name: "", keyword: "", technique: "" });
  }
  async function tune() {
    const ex = tuneText.trim(); if (!ex) return;
    const last = published[published.length - 1]?.payload as { name?: string } | undefined;
    setBusyTune(true); const ok = await act("rule.tuned", { rule: asStr(last?.name) || "last rule", exclusion: ex }); setBusyTune(false);
    if (ok) setTuneText("");
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldAlert className="h-4 w-4 text-cyber-300" /> Detection engineering</h3>
      <p className="mt-1 text-[11px] text-slate-400">Write a field-based rule mid-incident — it back-tests live against the feed.</p>
      <div className="mt-2 space-y-2">
        <input value={f.name} onChange={e => setF(s => ({ ...s, name: e.target.value }))} placeholder="Rule name" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={f.keyword} onChange={e => setF(s => ({ ...s, keyword: e.target.value }))} placeholder="Predicate (e.g. source:edr mitre:T1059, host:FIN-WS-07, PuTTY)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <p className="text-[10px] text-slate-500">fields: source · host · user · ip · mitre · rule · vendor · event · severity — AND-ed</p>
        {f.keyword.trim() && (
          <div className={`rounded border px-2 py-1 text-[11px] ${matched.length > 0 ? "border-neon-green/30 bg-neon-green/[0.05] text-neon-green" : "border-border text-slate-500"}`}>
            back-test: {matched.length} match{matched.length === 1 ? "" : "es"}
            {matched.length > 0 && <div className="mt-1 space-y-0.5">{matched.slice(0, 3).map(e => <p key={e.id} className="truncate font-mono text-[10px] text-slate-400">{e.source} · {asStr(e.displayDescription) || asStr(e.description) || e.event_type}</p>)}</div>}
          </div>
        )}
        <Button variant="primary" size="sm" disabled={busy || !f.name.trim() || !f.keyword.trim()} onClick={publish}>Publish rule</Button>
      </div>
      {published.length > 0 && <div className="mt-3 border-t border-border/50 pt-2 space-y-1">{published.map(r => { const p = r.payload as { name?: string; matched?: number; keyword?: string }; return <p key={r.seq} className="truncate text-[11px] text-slate-400"><span className="text-slate-200">{asStr(p.name)}</span> <span className="font-mono text-[10px]">{asStr(p.keyword)}</span> · {p.matched ?? 0} matched</p>; })}</div>}
      {/* Tune a rule — add an exclusion to cut false positives (rule.tuned) */}
      {published.length > 0 && (
        <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Tune a rule ({tuned.length})</p>
          <div className="flex gap-1.5">
            <input value={tuneText} onChange={e => setTuneText(e.target.value)} onKeyDown={e => { if (e.key === "Enter") tune(); }} placeholder="Exclusion to cut FPs (e.g. user:svc-backup)" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 font-mono text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
            <Button variant="outline" size="sm" disabled={busyTune || !tuneText.trim()} onClick={tune}>Tune</Button>
          </div>
        </div>
      )}
    </Card>
  );
}

// ── Threat Intel console — G-17: relevance + intel repository ─────────────────
// A tiny advisory repo the TI analyst must VET against the live evidence. One IOC
// is deliberately WRONG (a decoy) — publishing it as-is is the teaching mistake
// ("verify against the source, don't relay blindly").
const INTEL_REPO: Array<{ id: string; source: string; title: string; ioc: string; note?: string; decoy?: boolean }> = [
  { id: "a1", source: "CISA AA24-109A", title: "Trojanized SSH/PuTTY installers drop Cobalt Strike", ioc: "puttysoftware-download.com", note: "Matches the download domain in the feed." },
  { id: "a2", source: "Vendor blog", title: "FIN-actor exfil to mega.nz", ioc: "mega.nz", note: "Corroborate against DLP/proxy logs before acting." },
  { id: "a3", source: "OSINT (unverified)", title: "Reported C2 IP for this cluster", ioc: "8.8.8.8", note: "Single-source OSINT post; no corroboration listed. Verify against the feed before publishing.", decoy: true },
];
function TIConsole({ act }: { act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [f, setF] = useState({ actor: "", technique: "", confidence: "0.7", relevance: "medium", recommendation: "", next_expected: "", ioc: "" });
  const [busy, setBusy] = useState(false);
  async function publish() {
    if (!f.actor.trim() && !f.technique.trim()) return;
    setBusy(true); const ok = await act("intel.published", { ...f, confidence: Number(f.confidence) }); setBusy(false);
    if (ok) setF({ actor: "", technique: "", confidence: "0.7", relevance: "medium", recommendation: "", next_expected: "", ioc: "" });
  }
  return (
    <div className="space-y-4">
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Threat intel</h3>
        <p className="mt-1 text-[11px] text-slate-400">Turn indicators into context for the team — rate its relevance to THIS incident.</p>
        <div className="mt-2 space-y-2">
          <input value={f.actor} onChange={e => setF(s => ({ ...s, actor: e.target.value }))} placeholder="Actor / campaign" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.technique} onChange={e => setF(s => ({ ...s, technique: e.target.value }))} placeholder="Technique / TTP" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.ioc} onChange={e => setF(s => ({ ...s, ioc: e.target.value }))} placeholder="IOC (domain / IP / hash — verified)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 font-mono text-xs text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <input value={f.next_expected} onChange={e => setF(s => ({ ...s, next_expected: e.target.value }))} placeholder="Next expected step (predict)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          <div className="flex gap-2">
            <input value={f.recommendation} onChange={e => setF(s => ({ ...s, recommendation: e.target.value }))} placeholder="Recommended action" className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
          </div>
          <div className="flex gap-2">
            <select value={f.relevance} onChange={e => setF(s => ({ ...s, relevance: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"><option value="high">relevance: high</option><option value="medium">relevance: med</option><option value="low">relevance: low</option></select>
            <select value={f.confidence} onChange={e => setF(s => ({ ...s, confidence: e.target.value }))} className="flex-1 rounded-lg border border-border bg-bg px-2 py-1.5 text-xs text-slate-200 focus:outline-none"><option value="0.5">conf: low</option><option value="0.7">conf: med</option><option value="0.9">conf: high</option></select>
          </div>
          <Button variant="primary" size="sm" disabled={busy || (!f.actor.trim() && !f.technique.trim())} onClick={publish}>Publish intel</Button>
        </div>
      </Card>
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><FolderOpen className="h-4 w-4 text-cyber-300" /> Intel repository</h3>
        <p className="mt-1 text-[11px] text-slate-400">Vet each advisory against the feed before you relay it — not all IOCs are good.</p>
        <div className="mt-2 space-y-1.5">
          {INTEL_REPO.map(a => (
            <div key={a.id} className="rounded-lg border border-border bg-bg px-2 py-1.5 text-xs">
              <p className="text-slate-200">{a.title}</p>
              <p className="mt-0.5 font-mono text-[10px] text-slate-400">{a.ioc} · <span className="text-slate-500">{a.source}</span></p>
              {a.note && <p className="mt-0.5 text-[10px] text-slate-500">{a.note}</p>}
              <button onClick={() => setF(s => ({ ...s, ioc: a.ioc, actor: s.actor || a.title }))} className="mt-1 text-[10px] text-cyber-300 underline-offset-2 hover:underline">use this IOC →</button>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ── SOC Manager console ──────────────────────────────────────────────────────
function MgrConsole({ roster, events, act }: { roster: RosterMember[]; events: Ev[]; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  // G-16: structured passdown (App. D) instead of a free-text blob.
  const [ho, setHo] = useState({ open_cases: "", blockers: "", next: "" });
  const [busy, setBusy] = useState(false);
  const workload = roster.filter(r => r.role !== "instructor").map(m => ({
    name: m.name, role: m.role,
    actions: events.filter(e => e.actor_id === m.user_id && e.type !== "event.opened" && e.type !== "member.ready").length,
  }));
  const canPost = ho.open_cases.trim().length >= 5 && ho.next.trim().length >= 3;
  async function post() {
    if (!canPost) return;
    setBusy(true);
    // Compose a `text` summary so downstream (rubric completeness, activity) still reads a single field.
    const text = `Open: ${ho.open_cases.trim()} · Blockers: ${ho.blockers.trim() || "none"} · Next: ${ho.next.trim()}`;
    const ok = await act("handover.noted", { open_cases: ho.open_cases.trim(), blockers: ho.blockers.trim(), next: ho.next.trim(), text, summary: text });
    setBusy(false);
    if (ok) setHo({ open_cases: "", blockers: "", next: "" });
  }
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Users className="h-4 w-4 text-cyber-300" /> Shift management</h3>
      <div className="mt-2 space-y-1">
        {workload.map(w => (
          <div key={w.name} className="flex items-center justify-between text-xs">
            <span className="text-slate-300">{w.name} <span className="font-mono text-[10px] text-slate-500">{ROLE_LABEL[w.role] ?? w.role}</span></span>
            <span className="font-mono text-slate-400">{w.actions} actions</span>
          </div>
        ))}
      </div>
      <div className="mt-3 space-y-1.5 border-t border-border/50 pt-2">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Shift passdown</p>
        <textarea value={ho.open_cases} onChange={e => setHo(s => ({ ...s, open_cases: e.target.value }))} placeholder="Open cases (id · sev · status · last action)" rows={2} className="w-full resize-y rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={ho.blockers} onChange={e => setHo(s => ({ ...s, blockers: e.target.value }))} placeholder="Blockers (optional)" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <input value={ho.next} onChange={e => setHo(s => ({ ...s, next: e.target.value }))} placeholder="Next actions + deadline" className="w-full rounded-lg border border-border bg-bg px-2 py-1.5 text-sm text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
        <Button variant="primary" size="sm" disabled={busy || !canPost} onClick={post}>Sign passdown</Button>
      </div>
    </Card>
  );
}

// ── Team intel (shared — everyone sees published intel) ───────────────────────
function TeamIntel({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  const intel = events.filter(e => e.type === "intel.published");
  if (intel.length === 0) return null;
  return (
    <Card className="border-cyber-500/30">
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Siren className="h-4 w-4 text-cyber-300" /> Team intel</h3>
      <div className="mt-2 space-y-2">
        {intel.slice().reverse().map(e => {
          const p = e.payload as { actor?: string; technique?: string; next_expected?: string; recommendation?: string; confidence?: number };
          return (
            <div key={e.seq} className="rounded-lg border border-border bg-bg px-3 py-2 text-xs">
              <p className="text-slate-200">{[p.actor, p.technique].filter(Boolean).join(" · ") || "intel"}{p.confidence != null && <span className="ml-1 text-slate-500">conf {p.confidence}</span>}</p>
              {p.next_expected && <p className="mt-0.5 text-slate-400">next: {p.next_expected}</p>}
              {p.recommendation && <p className="mt-0.5 text-cyber-300">→ {p.recommendation}</p>}
              <p className="mt-0.5 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</p>
            </div>
          );
        })}
      </div>
    </Card>
  );
}

// ── After-action report (Phase 0.5) — derived entirely from the event log ────
const ATTACK_VERDICTS = new Set(["tp", "escalate"]);
interface UserReport {
  user_id: string; name: string; role: string;
  opened: number; avgDwellS: number | null; dispCount: number; dispCorrect: number; dispAcc: number | null;
  escCount: number; escQuality: number | null; acks: number; contReq: number; contDecided: number;
  roleActions: number; firstActionS: number | null; contribution: number;
  rubric: RubricCell[]; rubricPct: number | null;
}
const ROLE_ACTION_TYPES = new Set(["hunt.logged", "rule.published", "rule.tuned", "intel.published", "handover.noted", "decision.logged", "evidence.pinned", "case.status_set", "case.assigned", "note.added", "containment.executed", "scope.set", "scope.confirmed", "sitrep.sent", "ticket.answered", "escalation.resolved", "elevation.requested", "report.submitted"]);
function escQualityScore(p: Record<string, unknown>): number {
  // T1-4/5: structured report quality — summary + mechanism-bearing observations
  // (word count) + requested_action + severity + at least one IOC. `what`/`why`
  // are back-compat aliases of summary/observations.
  let s = 0;
  if (String(p.summary ?? p.what ?? "").trim()) s += 30;
  const whyWords = String(p.observations ?? p.why ?? "").trim().split(/\s+/).filter(Boolean).length;
  s += whyWords >= 20 ? 25 : whyWords >= 10 ? 15 : whyWords > 0 ? 8 : 0;
  if (String(p.requested_action ?? "").trim()) s += 15;
  if (p.severity || p.impact) s += 15;
  if (Array.isArray(p.iocs) ? p.iocs.length > 0 : false) s += 15;
  return Math.min(100, s);
}
/** T2 incident-report quality (deterministic, same spirit as escQualityScore):
 *  a substantive summary + findings (word count) + an explicit verdict + a
 *  recommendation. Feeds the T2 "Incident report" rubric cell (was un-measured). */
function reportQualityScore(p: Record<string, unknown>): number {
  // Spread the score so the 0/4/8/12 bands are all reachable ABOVE the submit floor
  // (summary + ≥12-word findings + recommendation). A bare-but-valid report lands
  // in the low band; depth (longer findings, a real recommendation, a cited
  // indicator) climbs it (G2). Substance beyond word-count is rewarded lightly by
  // requiring an indicator-looking token in the findings (G5, partial).
  let s = 0;
  if (String(p.summary ?? "").trim()) s += 15;
  const findings = String(p.findings ?? "").trim();
  const findingWords = findings.split(/\s+/).filter(Boolean).length;
  s += findingWords >= 60 ? 40 : findingWords >= 35 ? 30 : findingWords >= 20 ? 20 : findingWords >= 12 ? 12 : findingWords > 0 ? 5 : 0;
  if (String(p.verdict ?? "").trim()) s += 10;
  const recWords = String(p.recommendation ?? "").trim().split(/\s+/).filter(Boolean).length;
  s += recWords >= 12 ? 20 : recWords > 0 ? 10 : 0;
  // A cited indicator (IP / hash / domain / hostname) in the findings → substance bonus.
  const hasIoc = /(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{16,}\b|\b[a-z0-9-]+\.[a-z]{2,}\b|\b[A-Z]{2,}[-_][A-Z0-9-]+\b/i.test(findings);
  if (hasIoc) s += 15;
  return Math.min(100, s);
}
// ── G-11: per-role success rubric (0/4/8/12), §3.f–§9.f ──────────────────────
// Each role has 5 criteria. We score only the criteria whose source events exist
// today; criteria still awaiting instrumentation (🔜 in the spec) score `null`
// and are excluded from the % so a role isn't penalised for un-built plumbing.
export interface RubricCell { label: string; score: number | null; note?: string }
const bandHigh = (v: number, a: number, b: number, c: number) => (v >= a ? 12 : v >= b ? 8 : v >= c ? 4 : 0);
const bandLow = (v: number, a: number, b: number, c: number) => (v <= a ? 12 : v <= b ? 8 : v <= c ? 4 : 0);
function median(xs: number[]): number | null { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
const TODO: RubricCell = { label: "", score: null, note: "not yet measured" };
function rubricPercent(cells: RubricCell[]): number | null {
  const scored = cells.filter(c => c.score != null);
  if (!scored.length) return null;
  return Math.round((scored.reduce((s, c) => s + (c.score ?? 0), 0) / (scored.length * 12)) * 100);
}

interface RubricCtx {
  role: string; dispAcc: number | null; escAckRate: number | null; escPrecision: number | null; escRecall: number | null; escQuality: number | null;
  triageMin: number | null; ackLatencyMin: number | null; approvalLatencyMin: number | null;
  huntCount: number; huntTech: number; noteCount: number;
  rulePublished: number; ruleMatched: number; ruleTechniques: number; ruleDocRate: number | null;
  intelAttrib: number | null; intelNext: number | null;
  handoverComplete: number | null; reopens: number; workloadSkew: number | null;
  contReason: number | null; contTargetOk: number | null;
  scopeSetDims: number; scopeConfirmDims: number; scopeConfirmed: boolean;
  decisionCount: number; decisionRationaleRate: number | null;
  ticketsAnswered: number; sitrepCount: number; reportQuality: number | null;
  huntToConfirmMin: number | null; caseOwnedMin: number | null; mgmtRespondedRate: number | null;
}
function roleRubric(c: RubricCtx): RubricCell[] {
  switch (c.role) {
    case "t1": return [
      { label: "Disposition accuracy", score: c.dispAcc == null ? null : bandHigh(c.dispAcc, 90, 75, 50) },
      { label: "Escalation precision", score: c.escPrecision == null ? null : bandHigh(c.escPrecision, 80, 60, 40), note: "of what you escalated, how much was a real attack (vs ground truth)" },
      { label: "Attack recall (team)", score: c.escRecall == null ? null : bandHigh(c.escRecall, 80, 50, 25), note: "share of real attacks the T1 team escalated at all" },
      { label: "Card completeness", score: c.escQuality == null ? null : bandHigh(c.escQuality, 90, 70, 40) },
      { label: "Handoff coordination", score: c.escAckRate == null ? null : bandHigh(c.escAckRate, 80, 60, 40), note: "share of your escalations Tier-2 acknowledged" },
      { label: "Time-to-triage", score: c.triageMin == null ? null : bandLow(c.triageMin, 5, 10, 15) },
      { label: "Help-desk tickets", score: c.ticketsAnswered === 0 ? null : bandHigh(c.ticketsAnswered, 3, 2, 1) },
    ];
    case "t2": return [
      { label: "Ack latency", score: c.ackLatencyMin == null ? null : bandLow(c.ackLatencyMin, 2, 5, 10) },
      { ...TODO, label: "Timeline accuracy" },
      { label: "Scoping completeness", score: c.scopeSetDims >= 3 ? 12 : c.scopeSetDims >= 2 ? 8 : c.scopeSetDims >= 1 ? 4 : null },
      { label: "Containment recommendation", score: c.contReason == null ? null : bandHigh(c.contReason, 90, 60, 30) },
      { label: "Incident report", score: c.reportQuality == null ? null : bandHigh(c.reportQuality, 85, 60, 35) },
    ];
    case "t3": return [
      { label: "Final scope (confirmed)", score: c.scopeConfirmed ? (c.scopeConfirmDims >= 2 ? 8 : 4) : null, note: c.scopeConfirmed ? undefined : "not confirmed" },
      { label: "Hunt yield", score: bandHigh(c.huntCount, 3, 2, 1) },
      { label: "Hypothesis→conclusion time", score: c.huntToConfirmMin == null ? null : bandLow(c.huntToConfirmMin, 5, 12, 20) },
      { label: "Technique attribution", score: c.huntCount ? bandHigh(Math.round((c.huntTech / c.huntCount) * 100), 90, 60, 30) : null },
      // Secondary cell → null when there's nothing to measure (consistent with the
      // other quality cells; "Hunt yield" already carries the did-the-core-job signal) — G4.
      { label: "Guidance to T2", score: c.noteCount ? bandHigh(c.noteCount, 3, 2, 1) : null },
    ];
    case "lead": return [
      { label: "Team organised", score: c.caseOwnedMin == null ? null : bandLow(c.caseOwnedMin, 3, 8, 15) },
      { label: "Time-to-approval", score: c.approvalLatencyMin == null ? null : bandLow(c.approvalLatencyMin, 3, 7, 12) },
      { label: "Decision log", score: c.decisionCount === 0 ? null : c.decisionRationaleRate == null ? 4 : bandHigh(c.decisionRationaleRate, 90, 60, 30) },
      { label: "Cadence + SITREP", score: c.sitrepCount === 0 ? null : bandHigh(c.sitrepCount, 3, 2, 1) },
      { label: "Management pressure", score: c.mgmtRespondedRate == null ? null : bandHigh(c.mgmtRespondedRate, 100, 50, 1) },
    ];
    case "de": return [
      { label: "Verifiable rule", score: c.rulePublished ? bandHigh(c.ruleMatched, 3, 2, 1) : 0 },
      { ...TODO, label: "FP-rate" },
      { ...TODO, label: "Time-to-publish" },
      { label: "ATT&CK coverage-delta", score: c.rulePublished ? bandHigh(c.ruleTechniques, 3, 2, 1) : null },
      { label: "Documentation", score: c.ruleDocRate == null ? null : bandHigh(c.ruleDocRate, 90, 60, 30) },
    ];
    case "ti": return [
      { ...TODO, label: "Actionable-rate" },
      { ...TODO, label: "Time-to-action" },
      { label: "Attribution accuracy", score: c.intelAttrib == null ? null : bandHigh(c.intelAttrib, 90, 60, 30) },
      { label: "Next-step prediction", score: c.intelNext == null ? null : bandHigh(c.intelNext, 90, 60, 30) },
      { ...TODO, label: "IOC precision" },
    ];
    // In the 4-role model the SOC Manager IS the incident coordinator (approves
    // containment, logs decisions, sends SITREPs, organises the team), so the
    // rubric measures that coordinator work — all instrumented today.
    case "mgr": return [
      { label: "Team organised", score: c.caseOwnedMin == null ? null : bandLow(c.caseOwnedMin, 3, 8, 15) },
      { label: "Time-to-approval", score: c.approvalLatencyMin == null ? null : bandLow(c.approvalLatencyMin, 3, 7, 12) },
      { label: "Decision log", score: c.decisionCount === 0 ? null : c.decisionRationaleRate == null ? 4 : bandHigh(c.decisionRationaleRate, 90, 60, 30) },
      { label: "Cadence + SITREP", score: c.sitrepCount === 0 ? null : bandHigh(c.sitrepCount, 3, 2, 1) },
      { label: "Management pressure", score: c.mgmtRespondedRate == null ? null : bandHigh(c.mgmtRespondedRate, 100, 50, 1) },
    ];
    default: return [];
  }
}

function computeReport(events: Ev[], roster: RosterMember[]) {
  const started = events.find(e => e.type === "session.started");
  const startedMs = started?.occurred_at ? Date.parse(started.occurred_at)
    : events.length ? Math.min(...events.filter(e => e.occurred_at).map(e => Date.parse(e.occurred_at!))) : Date.now();
  const feed = events.filter(e => e.type === "feed.event");
  const gt = new Map<string, string | undefined>(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), (e.payload as { expected_verdict?: string }).expected_verdict]));
  const attackIds = new Set([...gt.entries()].filter(([, v]) => v && ATTACK_VERDICTS.has(v)).map(([k]) => k));
  // A4: team-wide recall — share of real attacks the T1 team escalated at all. A shared
  // metric (the queue is shared), so it doesn't unfairly punish one T1 for a teammate's catch.
  const teamEscalatedAttackIds = new Set(events.filter(e => e.type === "escalation.requested" && attackIds.has(String((e.payload as { event_id?: string }).event_id))).map(e => String((e.payload as { event_id?: string }).event_id)));
  const teamRecall = attackIds.size ? Math.round((teamEscalatedAttackIds.size / attackIds.size) * 100) : null;

  // Shared timing maps for the G-11 rubric (latencies derived from paired events).
  const feedTs = new Map<string, number | null>(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.occurred_at ? Date.parse(e.occurred_at) : null]));
  const feedSev = new Map<string, string>(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), String((e.payload as { severity?: string }).severity ?? "")]));
  const escReqTs = new Map<string, number | null>(events.filter(e => e.type === "escalation.requested").map(e => [String((e.payload as { event_id?: string }).event_id), e.occurred_at ? Date.parse(e.occurred_at) : null]));
  const contReqTs = new Map<string, number | null>(events.filter(e => e.type === "containment.requested").map(e => [String((e.payload as { event_id?: string }).event_id), e.occurred_at ? Date.parse(e.occurred_at) : null]));

  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");
  // Team-wide action counts (for the Mgr workload-balance criterion).
  const actionCountByUser = players.map(pl => events.filter(e => e.actor_id === pl.user_id && e.type !== "member.ready" && e.type !== "event.opened").length);
  const maxAction = Math.max(1, ...actionCountByUser);
  const avgAction = actionCountByUser.length ? actionCountByUser.reduce((s, n) => s + n, 0) / actionCountByUser.length : 0;
  const perUser: UserReport[] = players.map(m => {
    const mine = events.filter(e => e.actor_id === m.user_id);
    // G-01: event.opened now carries { event_id, dwell_ms }. Count DISTINCT feed
    // events opened (the row fires open+close for the same id), and take the max
    // dwell per id (the close transition carries the real expand→collapse time).
    const openedEvents = mine.filter(e => e.type === "event.opened");
    const dwellByEid = new Map<string, number>();
    for (const e of openedEvents) {
      const eid = String((e.payload as { event_id?: string }).event_id ?? "");
      if (!eid) continue;
      const d = Number((e.payload as { dwell_ms?: number }).dwell_ms ?? 0);
      dwellByEid.set(eid, Math.max(dwellByEid.get(eid) ?? 0, Number.isFinite(d) ? d : 0));
    }
    // Distinct ids opened; fall back to raw count for legacy empty-payload rows.
    const opened = dwellByEid.size || openedEvents.length;
    const dwellVals = [...dwellByEid.values()].filter(d => d > 0);
    const avgDwellS = dwellVals.length ? Math.round(dwellVals.reduce((s, d) => s + d, 0) / dwellVals.length / 1000) : null;
    const disp = mine.filter(e => e.type === "disposition.set");
    const dispCorrect = disp.filter(d => {
      const eid = String((d.payload as { event_id?: string }).event_id); const v = String((d.payload as { verdict?: string }).verdict);
      const isAttack = attackIds.has(eid);
      return isAttack ? v === "true_positive" : (v === "false_positive" || v === "benign");
    }).length;
    const esc = mine.filter(e => e.type === "escalation.requested");
    const escQuality = esc.length ? Math.round(esc.reduce((s, e) => s + escQualityScore(e.payload), 0) / esc.length) : null;
    const acks = mine.filter(e => e.type === "escalation.acknowledged").length;
    const contReq = mine.filter(e => e.type === "containment.requested").length;
    const contDecided = mine.filter(e => e.type === "containment.approved" || e.type === "containment.denied").length;
    const roleActions = mine.filter(e => ROLE_ACTION_TYPES.has(e.type)).length;
    const actionTimes = mine.filter(e => e.occurred_at && e.type !== "member.ready").map(e => Date.parse(e.occurred_at!));
    const firstActionS = actionTimes.length ? Math.max(0, Math.round((Math.min(...actionTimes) - startedMs) / 1000)) : null;
    const contribution = Math.min(100, opened * 3 + disp.length * 6 + esc.length * 15 + acks * 10 + contReq * 15 + contDecided * 20 + roleActions * 15);
    const dispAcc = disp.length ? Math.round((dispCorrect / disp.length) * 100) : null;

    // ── G-11 rubric context — measurable deltas for THIS user ──────────────────
    // A4: Escalation PRECISION vs ground truth — of this analyst's escalations, how many
    // were real attacks (scored at debrief only, so it never leaks live).
    const escPrecision = esc.length ? Math.round((esc.filter(e => attackIds.has(String((e.payload as { event_id?: string }).event_id))).length / esc.length) * 100) : null;
    // Handoff coordination (was mislabelled "precision"): share of this analyst's escalations
    // that a Tier-2 acknowledged. A coordination signal, not a correctness one.
    const escAckedIds = new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id)));
    const escAckRate = esc.length ? Math.round((esc.filter(e => escAckedIds.has(String((e.payload as { event_id?: string }).event_id))).length / esc.length) * 100) : null;
    // Time-to-triage: Δ(feed appearance → this user's disposition) for high/crit, minutes.
    const triageMin = median(disp.map(d => {
      const eid = String((d.payload as { event_id?: string }).event_id);
      const sev = feedSev.get(eid); if (sev !== "high" && sev !== "critical") return null;
      const ft = feedTs.get(eid); const dt = d.occurred_at ? Date.parse(d.occurred_at) : null;
      return ft != null && dt != null ? (dt - ft) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    // Ack latency: Δ(escalation.requested → this user's ack), minutes.
    const ackLatencyMin = median(mine.filter(e => e.type === "escalation.acknowledged").map(e => {
      const eid = String((e.payload as { event_id?: string }).event_id);
      const rt = escReqTs.get(eid); const at = e.occurred_at ? Date.parse(e.occurred_at) : null;
      return rt != null && at != null ? (at - rt) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    // Approval latency: Δ(containment.requested → this user's approve), minutes.
    const approvalLatencyMin = median(mine.filter(e => e.type === "containment.approved").map(e => {
      const eid = String((e.payload as { event_id?: string }).event_id);
      const rt = contReqTs.get(eid); const at = e.occurred_at ? Date.parse(e.occurred_at) : null;
      return rt != null && at != null ? (at - rt) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    // Hunt / rule / intel / handover payload signals.
    const hunts = mine.filter(e => e.type === "hunt.logged");
    const huntTech = hunts.filter(e => String((e.payload as { technique?: string }).technique ?? "").trim()).length;
    const noteCount = mine.filter(e => e.type === "note.added").length;
    const rules = mine.filter(e => e.type === "rule.published");
    const ruleMatched = rules.reduce((s, e) => s + Number((e.payload as { matched?: number }).matched ?? 0), 0);
    const ruleTechniques = new Set(rules.map(e => String((e.payload as { technique?: string }).technique ?? "")).filter(Boolean)).size;
    const ruleDocRate = rules.length ? Math.round((rules.filter(e => String((e.payload as { keyword?: string }).keyword ?? "").trim()).length / rules.length) * 100) : null;
    const intel = mine.filter(e => e.type === "intel.published");
    const intelAttrib = intel.length ? Math.round((intel.filter(e => { const p = e.payload as { actor?: string; technique?: string }; return String(p.actor ?? "").trim() && String(p.technique ?? "").trim(); }).length / intel.length) * 100) : null;
    const intelNext = intel.length ? Math.round((intel.filter(e => String((e.payload as { next_expected?: string }).next_expected ?? "").trim()).length / intel.length) * 100) : null;
    const handovers = mine.filter(e => e.type === "handover.noted");
    const handoverComplete = handovers.length ? Math.round((handovers.filter(e => String((e.payload as { text?: string }).text ?? "").trim().length >= 20).length / handovers.length) * 100) : null;
    const reopens = mine.filter(e => e.type === "case.status_set" && ["new", "triaged", "investigating"].includes(String((e.payload as { status?: string }).status))).length;
    const contReqEvents = mine.filter(e => e.type === "containment.requested");
    const contReason = contReqEvents.length ? Math.round((contReqEvents.filter(e => String((e.payload as { reason?: string }).reason ?? "").trim().length >= 10).length / contReqEvents.length) * 100) : null;
    const myActions = events.filter(e => e.actor_id === m.user_id && e.type !== "member.ready" && e.type !== "event.opened").length;
    const workloadSkew = avgAction > 0 ? Math.round((Math.abs(myActions - avgAction) / maxAction) * 100) : null;
    // G-10 scope scoring: count filled dimensions (hosts/users/techniques) in this user's best scope event.
    const dimsOf = (e: Ev) => { const p = e.payload as { hosts?: string[]; users?: string[]; techniques?: string[] }; return (p.hosts?.length ? 1 : 0) + (p.users?.length ? 1 : 0) + (p.techniques?.length ? 1 : 0); };
    const scopeSets = mine.filter(e => e.type === "scope.set");
    const scopeConfirms = mine.filter(e => e.type === "scope.confirmed");
    const scopeSetDims = scopeSets.length ? Math.max(...scopeSets.map(dimsOf)) : 0;
    const scopeConfirmDims = scopeConfirms.length ? Math.max(...scopeConfirms.map(dimsOf)) : 0;
    // G-15 decision-log scoring: share of this user's decisions that carry a rationale.
    const decisions = mine.filter(e => e.type === "decision.logged");
    const decisionRationaleRate = decisions.length ? Math.round((decisions.filter(e => String((e.payload as { rationale?: string }).rationale ?? "").trim().length >= 5).length / decisions.length) * 100) : null;
    const ticketsAnswered = mine.filter(e => e.type === "ticket.answered").length;
    const sitrepCount = mine.filter(e => e.type === "sitrep.sent").length;
    const reports = mine.filter(e => e.type === "report.submitted");
    const reportQuality = reports.length ? Math.round(reports.reduce((s, e) => s + reportQualityScore(e.payload), 0) / reports.length) : null;
    // T3: hypothesis→conclusion latency — first hunt logged → first scope confirmed.
    const tms = (es: Ev[]) => es.map(e => e.occurred_at ? Date.parse(e.occurred_at) : NaN).filter(n => Number.isFinite(n));
    const firstHuntTs = tms(hunts).length ? Math.min(...tms(hunts)) : null;
    const firstConfirmTs = tms(scopeConfirms).length ? Math.min(...tms(scopeConfirms)) : null;
    const huntToConfirmMin = firstHuntTs != null && firstConfirmTs != null && firstConfirmTs >= firstHuntTs ? (firstConfirmTs - firstHuntTs) / 60000 : null;
    // Mgr "team organised": how soon the case got an explicit owner (case.assigned).
    const caseAssigns = mine.filter(e => e.type === "case.assigned");
    const caseOwnedMin = tms(caseAssigns).length ? Math.max(0, (Math.min(...tms(caseAssigns)) - startedMs) / 60000) : null;
    // Mgr "management pressure": share of mgmt-pressure injects answered by a SITREP.
    // G6: pair each inject to a DISTINCT following SITREP (one-to-one, within 15 min),
    // so one late/unrelated SITREP can't be counted as answering every inject.
    const mgmtInjects = events.filter(e => e.type === "staff.inject" && String((e.payload as { kind?: string }).kind) === "mgmt_pressure");
    const injTs = tms(mgmtInjects).sort((a, b) => a - b);
    const sitrepPool = tms(mine.filter(e => e.type === "sitrep.sent")).sort((a, b) => a - b);
    const MGMT_WINDOW = 15 * 60000;
    let mgmtAnswered = 0;
    for (const it of injTs) {
      const idx = sitrepPool.findIndex(st => st >= it && st - it <= MGMT_WINDOW);
      if (idx !== -1) { mgmtAnswered++; sitrepPool.splice(idx, 1); }
    }
    const mgmtRespondedRate = mgmtInjects.length ? Math.round((mgmtAnswered / mgmtInjects.length) * 100) : null;

    const rubric = roleRubric({
      role: m.role, dispAcc, escAckRate, escPrecision, escRecall: teamRecall, escQuality, triageMin, ackLatencyMin, approvalLatencyMin,
      huntCount: hunts.length, huntTech, noteCount, rulePublished: rules.length, ruleMatched, ruleTechniques, ruleDocRate,
      intelAttrib, intelNext, handoverComplete, reopens, workloadSkew, contReason, contTargetOk: null,
      scopeSetDims, scopeConfirmDims, scopeConfirmed: scopeConfirms.length > 0,
      decisionCount: decisions.length, decisionRationaleRate,
      ticketsAnswered, sitrepCount, reportQuality,
      huntToConfirmMin, caseOwnedMin, mgmtRespondedRate,
    });
    const rubricPct = rubricPercent(rubric);

    return {
      user_id: m.user_id, name: m.name, role: m.role, opened, avgDwellS,
      dispCount: disp.length, dispCorrect, dispAcc,
      escCount: esc.length, escQuality, acks, contReq, contDecided, roleActions, firstActionS, contribution,
      rubric, rubricPct,
    };
  });

  const escReq = events.filter(e => e.type === "escalation.requested");
  const detectEsc = escReq.filter(e => attackIds.has(String((e.payload as { event_id?: string }).event_id)));
  const detected = detectEsc.length > 0;
  const firstDetect = detectEsc.map(e => e.occurred_at ? Date.parse(e.occurred_at) : Infinity).sort((a, b) => a - b)[0];
  const timeToDetectS = detected && isFinite(firstDetect) ? Math.max(0, Math.round((firstDetect - startedMs) / 1000)) : null;
  const dispAll = events.filter(e => e.type === "disposition.set");
  const dispAllCorrect = dispAll.filter(d => { const eid = String((d.payload as { event_id?: string }).event_id); const v = String((d.payload as { verdict?: string }).verdict); const a = attackIds.has(eid); return a ? v === "true_positive" : (v === "false_positive" || v === "benign"); }).length;

  const caseStatusEvt = [...events].reverse().find(e => e.type === "case.status_set");
  // G-09 MTTC: Δ(containment.requested → containment.executed) per event, median seconds.
  const execEvents = events.filter(e => e.type === "containment.executed");
  const mttcS = median(execEvents.map(e => {
    const eid = String((e.payload as { event_id?: string }).event_id);
    const rt = contReqTs.get(eid); const xt = e.occurred_at ? Date.parse(e.occurred_at) : null;
    return rt != null && xt != null ? (xt - rt) / 1000 : null;
  }).filter((x): x is number => x != null && x >= 0));
  const team = {
    logs: feed.length, attacks: attackIds.size, detected, timeToDetectS,
    escalations: escReq.length, acknowledged: events.filter(e => e.type === "escalation.acknowledged").length,
    containmentReq: events.filter(e => e.type === "containment.requested").length,
    contained: events.filter(e => e.type === "containment.approved").length,
    executed: execEvents.length, mttcS: mttcS != null ? Math.round(mttcS) : null,
    dispTotal: dispAll.length, dispAcc: dispAll.length ? Math.round((dispAllCorrect / dispAll.length) * 100) : null,
    caseStatus: (caseStatusEvt?.payload as { status?: string })?.status ?? "—",
    evidencePinned: events.filter(e => e.type === "evidence.pinned").length,
  };
  return { team, perUser };
}

// ── Guided hot-wash (§6.6) — a dual-track replay reconstructed from the event log:
// attack activity vs the team's response, key moments, and reflection prompts. This
// is the "conversation, not a scorecard" half of the debrief (research: a guided
// debrief ≈ half the learning). All derived from `events`, no new instrumentation.
function HotWash({ events, nameOf }: { events: Ev[]; nameOf: (u: string | null) => string }) {
  // Anchor relative times to session START (not events[0], which is the earliest
  // lobby member.ready — that inflated every time and disagreed with the AAR). Fall
  // back to the first event's timestamp only if there's no session.started (G1).
  const startedEv = events.find(e => e.type === "session.started");
  const t0 = startedEv?.occurred_at ? Date.parse(startedEv.occurred_at)
    : (events.length && events[0].occurred_at ? Date.parse(events[0].occurred_at) : 0);
  const rel = (ts?: string) => (ts && t0 ? Math.max(0, Math.round((Date.parse(ts) - t0) / 1000)) : 0);
  const fmt = (s: number) => (s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`);
  const RESPONSE_LABEL: Record<string, string> = {
    "escalation.requested": "escalated to Tier-2", "escalation.acknowledged": "acknowledged", "escalation.bounced": "bounced back",
    "elevation.requested": "elevated to Tier-3", "containment.requested": "requested containment", "containment.approved": "approved containment",
    "containment.denied": "denied containment", "containment.executed": "executed isolation", "decision.logged": "logged a decision",
    "sitrep.sent": "sent a SITREP", "scope.confirmed": "confirmed scope",
  };
  const rows = useMemo(() => {
    const out: { t: number; track: "attack" | "response"; label: string; who?: string }[] = [];
    for (const e of events) {
      const p = e.payload as Record<string, unknown>;
      if (e.type === "feed.event" && (p.expected_verdict === "tp" || p.expected_verdict === "escalate")) {
        out.push({ t: rel(e.occurred_at), track: "attack", label: asStr(p.description) || asStr(p.event_type) || "attack activity" });
      } else if (RESPONSE_LABEL[e.type]) {
        out.push({ t: rel(e.occurred_at), track: "response", label: RESPONSE_LABEL[e.type], who: nameOf(e.actor_id) });
      }
    }
    return out.sort((a, b) => a.t - b.t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events]);

  const firstAttack = events.find(e => e.type === "feed.event" && ((e.payload as Record<string, unknown>).expected_verdict === "tp" || (e.payload as Record<string, unknown>).expected_verdict === "escalate"));
  const firstEsc = events.find(e => e.type === "escalation.requested");
  const decision = events.find(e => e.type === "containment.approved" || e.type === "containment.denied");
  const exec = events.find(e => e.type === "containment.executed");
  const dwellS = firstAttack && firstEsc ? rel(firstEsc.occurred_at) - rel(firstAttack.occurred_at) : null;

  const moments: { t: string; title: string; note: string }[] = [];
  if (firstEsc) moments.push({ t: fmt(rel(firstEsc.occurred_at)), title: "First escalation", note: `${nameOf(firstEsc.actor_id)} raised the first case${dwellS != null && dwellS >= 0 ? ` — ${fmt(dwellS)} after the attack first showed in the feed` : ""}.` });
  if (decision) moments.push({ t: fmt(rel(decision.occurred_at)), title: decision.type === "containment.approved" ? "Containment approved" : "Containment denied", note: `${nameOf(decision.actor_id)} made the call.` });
  if (exec) moments.push({ t: fmt(rel(exec.occurred_at)), title: "Host isolated", note: `${nameOf(exec.actor_id)} executed the containment.` });

  if (rows.length === 0) return null;
  return (
    <Card>
      <h3 className="flex items-center gap-2 text-sm font-bold text-white"><Clock className="h-4 w-4 text-cyber-300" /> Hot-wash — what happened, and when</h3>
      <p className="mt-1 text-[11px] text-slate-400">Attack activity vs the team&apos;s response, side by side. Use it to talk through the timeline together.</p>

      {moments.length > 0 && (
        <div className="mt-3 grid gap-2 sm:grid-cols-3">
          {moments.map((m, i) => (
            <div key={i} className="rounded-lg border border-cyber-500/30 bg-cyber-500/[0.06] px-3 py-2">
              <p className="font-mono text-[10px] text-cyber-300">{m.t}</p>
              <p className="text-[11px] font-semibold text-white">{m.title}</p>
              <p className="text-[10px] text-slate-400 leading-snug">{m.note}</p>
            </div>
          ))}
        </div>
      )}

      {/* Dual-track timeline: attack on the left, response on the right */}
      <div className="mt-3 max-h-72 overflow-y-auto rounded-lg border border-border/50 bg-bg">
        {rows.map((r, i) => (
          <div key={i} className="flex items-stretch gap-2 border-b border-border/30 px-2 py-1 text-[11px] last:border-0">
            <span className="w-14 shrink-0 pt-0.5 text-right font-mono text-[10px] text-slate-500">{fmt(r.t)}</span>
            <div className="min-w-0 flex-1">
              {r.track === "attack"
                ? <div className="rounded border-l-2 border-severity-high/60 bg-severity-high/[0.06] px-2 py-1 text-severity-high/90"><span className="text-[9px] font-bold uppercase tracking-wider text-severity-high/70">attack</span> {r.label}</div>
                : <div className="ms-auto w-[85%] rounded border-l-2 border-cyber-500/60 bg-cyber-500/[0.06] px-2 py-1 text-slate-200"><span className="text-[9px] font-bold uppercase tracking-wider text-cyber-300/80">{r.who}</span> {r.label}</div>}
            </div>
          </div>
        ))}
      </div>

      {/* Reflection prompts — the discussion, not a grade */}
      <div className="mt-3 rounded-lg border border-border/50 bg-bg-elevated/40 px-3 py-2.5">
        <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Debrief together</p>
        <ul className="mt-1 list-disc space-y-1 pl-4 text-[11px] text-slate-300">
          <li>What was the earliest log that should have tipped us off — did we catch it, or walk past it?</li>
          <li>Where did the hand-offs slow down (T1→T2→Manager→execute), and why?</li>
          <li>If this were real, what would we do differently in the first five minutes?</li>
        </ul>
      </div>
    </Card>
  );
}

function TeamReport({ events, roster, me }: { events: Ev[]; roster: RosterMember[]; me: Me }) {
  const { team, perUser } = useMemo(() => computeReport(events, roster), [events, roster]);
  // A5: staff AND the SOC Manager (the coordinator who runs the debrief) see the whole
  // team's cards; other players see only their own.
  const seesAll = me.is_staff || me.role === "mgr";
  const visible = seesAll ? perUser : perUser.filter(u => u.user_id === me.id);

  function exportCsv() {
    const header = ["Name", "Role", "Rubric score %", "Logs opened", "Avg dwell (s)", "Dispositions", "Disposition accuracy %", "Escalations", "Escalation quality", "Acks", "Containment requests", "Containment decisions", "Role actions", "First action (s)", "Contribution"];
    const rows = perUser.map(u => [u.name, u.role, u.rubricPct ?? "", u.opened, u.avgDwellS ?? "", u.dispCount, u.dispAcc ?? "", u.escCount, u.escQuality ?? "", u.acks, u.contReq, u.contDecided, u.roleActions, u.firstActionS ?? "", u.contribution].map(String));
    const csv = [header, ...rows].map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8;" }));
    const a = document.createElement("a"); a.href = url; a.download = `team-exercise-report-${new Date().toISOString().slice(0, 10)}.csv`; a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="space-y-5">
      <Card className={team.detected ? "border-neon-green/30" : "border-neon-amber/30"}>
        <div className="flex items-center justify-between">
          <h2 className="text-base font-bold text-white">After-action report</h2>
          {me.is_staff && <Button variant="outline" size="sm" onClick={exportCsv}>Export CSV</Button>}
        </div>
        <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
          <Metric label="Attack detected" value={team.detected ? "Yes" : "No"} tone={team.detected ? "good" : "warn"} />
          <Metric label="Time to detect" value={team.timeToDetectS != null ? `${team.timeToDetectS}s` : "—"} />
          <Metric label="Logs" value={String(team.logs)} />
          <Metric label="Disposition acc." value={team.dispAcc != null ? `${team.dispAcc}%` : "—"} />
          <Metric label="Escalations" value={String(team.escalations)} />
          <Metric label="Acknowledged" value={String(team.acknowledged)} />
          <Metric label="Containment req." value={String(team.containmentReq)} />
          <Metric label="Contained" value={String(team.contained)} tone={team.contained > 0 ? "good" : undefined} />
          <Metric label="Isolated (exec)" value={String(team.executed)} tone={team.executed > 0 ? "good" : undefined} />
          <Metric label="MTTC" value={team.mttcS != null ? `${team.mttcS}s` : "—"} />
          <Metric label="Case status" value={team.caseStatus} tone={team.caseStatus === "closed" || team.caseStatus === "contained" ? "good" : undefined} />
          <Metric label="Evidence pinned" value={String(team.evidencePinned)} />
        </div>
      </Card>

      {/* Guided hot-wash — the debrief conversation, reconstructed from the log */}
      <HotWash events={events} nameOf={(u) => roster.find(r => r.user_id === u)?.name ?? "someone"} />

      <div className="grid gap-3 sm:grid-cols-2">
        {visible.map(u => (
          <Card key={u.user_id}>
            <div className="flex items-center justify-between">
              <p className="text-sm font-bold text-white">{u.name}</p>
              <span className="rounded border border-border px-1.5 py-0.5 font-mono text-[10px] text-slate-400">{ROLE_LABEL[u.role] ?? u.role}</span>
            </div>
            {/* G-11: role rubric is the real score; contribution kept as a secondary signal */}
            <div className="mt-2 flex items-center gap-2">
              <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg"><span className="block h-full bg-cyber-500" style={{ width: `${u.rubricPct ?? 0}%` }} /></div>
              <span className="shrink-0 font-mono text-xs font-bold text-cyber-300">{u.rubricPct != null ? `${u.rubricPct}` : "—"}<span className="text-slate-500">/100</span></span>
            </div>
            <p className="mt-1 text-[10px] text-slate-500">role rubric score · contribution {u.contribution}/100</p>
            {u.rubric.length > 0 && (
              <div className="mt-2 space-y-1">
                {u.rubric.map(cell => (
                  <div key={cell.label} className="flex items-center gap-2 text-[11px]">
                    <span className="min-w-0 flex-1 truncate text-slate-400">{cell.label}</span>
                    {cell.score == null
                      ? <span className="shrink-0 rounded border border-border/60 px-1 py-0.5 text-[9px] uppercase text-slate-600">{cell.note ?? "n/a"}</span>
                      : <span className={`shrink-0 rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${cell.score >= 12 ? "bg-neon-green/15 text-neon-green" : cell.score >= 8 ? "bg-cyber-500/15 text-cyber-300" : cell.score >= 4 ? "bg-neon-amber/15 text-neon-amber" : "bg-severity-high/15 text-severity-high"}`}>{cell.score}</span>}
                  </div>
                ))}
              </div>
            )}
            <div className="mt-3 grid grid-cols-2 gap-2 border-t border-border/40 pt-2 text-xs">
              <Line label="Logs opened" value={String(u.opened)} />
              <Line label="Avg dwell" value={u.avgDwellS != null ? `${u.avgDwellS}s` : "—"} />
              <Line label="First action" value={u.firstActionS != null ? `${u.firstActionS}s` : "—"} />
              <Line label="Dispositions" value={`${u.dispCount}${u.dispAcc != null ? ` · ${u.dispAcc}%` : ""}`} />
              <Line label="Escalations" value={`${u.escCount}${u.escQuality != null ? ` · q${u.escQuality}` : ""}`} />
              <Line label="Acknowledged" value={String(u.acks)} />
              <Line label="Containment" value={`${u.contReq} req · ${u.contDecided} dec`} />
              <Line label="Role actions" value={String(u.roleActions)} />
            </div>
          </Card>
        ))}
      </div>
      <p className="text-xs text-slate-500">Per-user rubric (0/4/8/12 per criterion, §3.f–§9.f) + team report from the action log. Criteria marked n/a await instrumentation (scope.set, SITREP, report grading).</p>
    </div>
  );
}
function Metric({ label, value, tone }: { label: string; value: string; tone?: "good" | "warn" }) {
  return <div className="rounded-lg border border-border bg-bg px-3 py-2"><p className="text-[10px] uppercase tracking-wider text-slate-400">{label}</p><p className={`mt-0.5 font-mono text-lg font-bold ${tone === "good" ? "text-neon-green" : tone === "warn" ? "text-neon-amber" : "text-white"}`}>{value}</p></div>;
}
function Line({ label, value }: { label: string; value: string }) {
  return <div className="flex items-center justify-between border-b border-border/40 pb-1"><span className="text-slate-400">{label}</span><span className="font-mono text-slate-200">{value}</span></div>;
}

// ── Team activity log (everyone sees the coordination) ───────────────────────
function ActivityLog({ activity, nameOf }: { activity: Ev[]; nameOf: (u: string | null) => string }) {
  const label = (e: Ev) => {
    const p = e.payload as Record<string, unknown>;
    switch (e.type) {
      case "disposition.set": return `marked a log ${String(p.verdict).replace("_", " ")}`;
      case "escalation.requested": return `escalated: ${p.what}`;
      case "escalation.acknowledged": return "acknowledged an escalation";
      case "elevation.requested": return `elevated to Tier-3: ${p.summary ?? p.what ?? "a case"}`;
      case "report.submitted": return `submitted an incident report: ${p.summary ?? ""}`;
      case "containment.requested": return `requested containment of ${p.target}`;
      case "containment.approved": return "approved containment";
      case "containment.denied": return "denied containment";
      case "containment.executed": return `executed isolation on ${asStr((p as { target?: string }).target) || "the host"}`;
      case "escalation.bounced": return "bounced an escalation back to Tier-1";
      case "escalation.resolved": return "resolved an escalation";
      case "scope.set": return "set the incident scope";
      case "scope.confirmed": return "confirmed the final scope";
      case "sitrep.sent": return "sent a SITREP";
      case "staff.inject": return `posted an inject (${asStr((p as { kind?: string }).kind) || "announcement"})`;
      case "ticket.answered": return `answered a help-desk ticket (${asStr((p as { decision?: string }).decision) || "handled"})`;
      case "hunt.logged": return `logged a hunt finding${p.technique ? ` (${p.technique})` : ""}`;
      case "rule.published": return `published detection rule "${p.name}" (${p.matched ?? 0} matches)`;
      case "intel.published": return `published intel${p.actor ? `: ${p.actor}` : ""}`;
      case "handover.noted": return "posted a handover note";
      case "decision.logged": return "logged a decision";
      case "evidence.pinned": return `pinned evidence to the case${p.summary ? `: ${String(p.summary).slice(0, 40)}` : ""}`;
      case "case.status_set": return `set case status → ${p.status}`;
      case "case.assigned": return "assigned the case owner";
      case "note.added": return "added a case note";
      default: return e.type;
    }
  };
  return (
    <Card>
      <h3 className="text-sm font-bold text-white">Team activity</h3>
      {activity.length === 0 ? <p className="mt-2 text-xs text-slate-400">Actions your team takes appear here, live.</p> : (
        <div className="mt-2 max-h-64 space-y-1.5 overflow-y-auto">
          {activity.slice().reverse().map(e => (
            <p key={e.seq} className="text-[11px] text-slate-400"><span className="font-medium text-slate-200">{nameOf(e.actor_id)}</span> {label(e)}</p>
          ))}
        </div>
      )}
    </Card>
  );
}

// ── G-04: surfaced feed filters + active pivot chips ─────────────────────────
type PivotTuple = ["user" | "host" | "ip", string, (v: string) => void];
function FeedFilterBar({
  severity, setSeverity, source, setSource, sources, search, setSearch, pivots,
}: {
  severity: "all" | "low" | "medium" | "high"; setSeverity: (v: "all" | "low" | "medium" | "high") => void;
  source: string; setSource: (v: string) => void; sources: string[];
  search: string; setSearch: (v: string) => void;
  pivots: PivotTuple[];
}) {
  const activePivots = pivots.filter(([, v]) => v !== "all");
  const SEV: Array<{ k: "all" | "low" | "medium" | "high"; label: string }> = [
    { k: "all", label: "All" }, { k: "high", label: "High" }, { k: "medium", label: "Med" }, { k: "low", label: "Low" },
  ];
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-lg border border-border bg-bg-elevated/60 px-3 py-2">
      <Filter className="h-3.5 w-3.5 shrink-0 text-slate-400" />
      <div className="flex items-center gap-1">
        {SEV.map(s => (
          <button key={s.k} onClick={() => setSeverity(s.k)}
            className={`rounded px-2 py-0.5 text-[10px] font-semibold transition ${severity === s.k ? "border border-cyber-500/40 bg-cyber-500/20 text-cyber-300" : "border border-transparent text-slate-400 hover:text-slate-200"}`}>{s.label}</button>
        ))}
      </div>
      <select value={source} onChange={e => setSource(e.target.value)}
        className="rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 focus:outline-none">
        <option value="all">All sources</option>
        {sources.map(s => <option key={s} value={s}>{s}</option>)}
      </select>
      <div className="relative min-w-[120px] flex-1">
        <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search feed… (host:… user:…)"
          className="w-full rounded border border-border bg-bg px-2 py-1 text-[11px] text-slate-200 placeholder:text-slate-500 focus:border-cyber-500/50 focus:outline-none" />
      </div>
      {activePivots.map(([field, value, setter]) => (
        <button key={field} onClick={() => setter("all")} title="Clear this filter"
          className="flex items-center gap-1 rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-0.5 text-[10px] font-mono text-cyber-300 hover:bg-cyber-500/20">
          {field}:{value} <X className="h-3 w-3" />
        </button>
      ))}
    </div>
  );
}

// ── G-08: Lead/Mgr Situation Board — summaries only, never raw (§3.7) ─────────
function SituationBoard({ liveFeed, events, feed, nameOf }: { liveFeed: LiveEvent[]; events: Ev[]; feed: Ev[]; nameOf: (u: string | null) => string }) {
  const pulse = useMemo(() => {
    let high = 0, med = 0, low = 0;
    for (const e of liveFeed) { const l = e.ruleLevel ?? 1; if (l >= 7) high++; else if (l >= 4) med++; else low++; }
    return { high, med, low, total: liveFeed.length };
  }, [liveFeed]);
  const bySource = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of liveFeed) { const s = e.source || "other"; m.set(s, (m.get(s) ?? 0) + 1); }
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [liveFeed]);
  const feedById = useMemo(() => new Map(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.payload as Record<string, unknown>])), [feed]);
  const escs = useMemo(() => events.filter(e => e.type === "escalation.requested"), [events]);
  const ackedIds = useMemo(() => new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id))), [events]);
  return (
    <div className="space-y-3">
      <Card>
        <h2 className="flex items-center gap-2 text-sm font-bold text-white"><ShieldCheck className="h-4 w-4 text-cyber-300" /> Situation Board</h2>
        <p className="mt-0.5 text-[11px] text-slate-500">Coordinator view — summaries, not raw logs. Direct your team; don&apos;t dive into the feed.</p>
        <div className="mt-3 grid grid-cols-4 gap-2">
          <Metric label="Logs" value={String(pulse.total)} />
          <Metric label="High" value={String(pulse.high)} tone={pulse.high > 0 ? "warn" : undefined} />
          <Metric label="Medium" value={String(pulse.med)} />
          <Metric label="Low" value={String(pulse.low)} />
        </div>
        <div className="mt-3">
          <p className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">Top sources</p>
          <div className="flex flex-wrap gap-1">
            {bySource.length === 0 ? <span className="text-[11px] text-slate-600">—</span> : bySource.map(([s, n]) => (
              <span key={s} className="rounded bg-white/5 px-1.5 py-0.5 font-mono text-[10px] text-slate-300">{s} · {n}</span>
            ))}
          </div>
        </div>
      </Card>
      <Card>
        <h3 className="flex items-center gap-2 text-sm font-bold text-white"><ArrowUpRight className="h-4 w-4 text-neon-amber" /> Escalation queue ({escs.length})</h3>
        {escs.length === 0 ? <p className="mt-2 text-xs text-slate-500">No escalations from Tier-1 yet.</p> : (
          <div className="mt-2 max-h-[420px] space-y-1.5 overflow-y-auto">
            {escs.slice().reverse().map(e => {
              const p = e.payload as { what?: string; event_id?: string; impact?: string };
              const fe = feedById.get(String(p.event_id)) as { severity?: string; hostname?: string } | undefined;
              const isAck = ackedIds.has(String(p.event_id));
              return (
                <div key={e.seq} className="flex items-center gap-2 rounded border border-border/60 bg-bg px-2 py-1.5 text-xs">
                  <span className={`h-1.5 w-1.5 shrink-0 rounded-full ${sevColor(fe?.severity)}`} />
                  <span className="min-w-0 flex-1 truncate text-slate-300">{asStr(p.what) || "escalation"}{fe?.hostname ? ` · ${fe.hostname}` : ""}</span>
                  <span className="shrink-0 font-mono text-[10px] text-slate-500">{nameOf(e.actor_id)}</span>
                  <span className={`shrink-0 rounded border px-1 py-0.5 text-[9px] font-bold uppercase ${isAck ? "border-neon-green/40 bg-neon-green/10 text-neon-green" : "border-neon-amber/40 bg-neon-amber/10 text-neon-amber"}`}>{isAck ? "ack" : "open"}</span>
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── G-03: secondary shared panels folded into tabs so the role panel stays dominant ──
// (G-13 adds the war-room chat as a third tab.)
function SecondaryPanels({ events, activity, me, nameOf, act }: { events: Ev[]; activity: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<"activity" | "chat" | "intel">("activity");
  const chatCount = useMemo(() => events.filter(e => e.type === "message.sent").length, [events]);
  return (
    <Card>
      <button onClick={() => setOpen(o => !o)} className="flex w-full items-center gap-2 text-left">
        <ChevronDown className={`h-4 w-4 text-slate-400 transition-transform ${open ? "" : "-rotate-90"}`} />
        <span className="text-sm font-bold text-white">Team context</span>
        <span className="ml-auto text-[10px] text-slate-500">{activity.length} actions · {chatCount} chat · intel</span>
      </button>
      {open && (
        <div className="mt-3">
          <div className="mb-2 flex gap-1">
            {(["activity", "chat", "intel"] as const).map(t => (
              <button key={t} onClick={() => setTab(t)}
                className={`rounded px-2 py-0.5 text-[11px] font-semibold capitalize transition ${tab === t ? "border border-cyber-500/40 bg-cyber-500/10 text-cyber-300" : "border border-transparent text-slate-400 hover:text-slate-200"}`}>{t === "chat" ? "War room" : t}</button>
            ))}
          </div>
          {tab === "activity" ? <ActivityLog activity={activity} nameOf={nameOf} />
            : tab === "chat" ? <WarRoom events={events} me={me} nameOf={nameOf} act={act} />
            : <TeamIntel events={events} nameOf={nameOf} />}
        </div>
      )}
    </Card>
  );
}

// ── G-13: war-room — a durable team chat (message.sent is already gate-allowed) ──
function WarRoom({ events, me, nameOf, act }: { events: Ev[]; me: Me; nameOf: (u: string | null) => string; act: (t: string, p: Record<string, unknown>) => Promise<boolean> }) {
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

