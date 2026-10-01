"use client";
import { useCallback, useEffect, useRef, useState } from "react";
import type { TelemetryEvent } from "@/lib/sim/types";
import {
  initWorldState, generateBenignEvent,
  pickPlaybook, startAttack, advanceAttack, attackDue,
} from "@/lib/sim/engine";
import type { WorldState, GeneratedEvent } from "@/lib/sim/engine";
import type { AttackStory } from "./attackStories";
import { appendDashboardSession } from "@/lib/storage/progress";
import { withRebasedTime } from "@/lib/sim/rebaseTime";


/**
 * Event times for a batch that arrives together (one attack phase): spread over the
 * last minute or two and strictly in story order, the newest a few seconds before
 * now. A log is never stamped in the future — ingestion lag makes it arrive AFTER it
 * happened, not before (the old stamping added the lag to the event time).
 */
export function phaseTimes(n: number, now: number, rnd: () => number = Math.random): number[] {
  const out: number[] = new Array(n);
  let t = now - (5_000 + Math.floor(rnd() * 15_000));          // newest: 5-20 s ago
  for (let i = n - 1; i >= 0; i--) { out[i] = t; t -= 20_000 + Math.floor(rnd() * 25_000); } // 20-45 s apart
  return out;
}

/** Newest first by event time (stable): a log that arrives late slots into its place, as in a SIEM. */
export function mergeByTime<T extends { ts?: string }>(batch: T[], prev: T[], max: number): T[] {
  return [...batch, ...prev]
    .map((e, i) => { const t = Date.parse(e.ts ?? ""); return { e, i, t: Number.isFinite(t) ? t : Infinity }; })
    .sort((a, b) => b.t - a.t || a.i - b.i)
    .slice(0, max)
    .map(x => x.e);
}

export interface ActiveIncident {
  id: string;
  title: string;
  severity: "critical" | "high";
  injectedAt: number;     // Date.now()
  eventIds: string[];     // IDs of the injected attack events
}

/**
 * Teaching payload for the POSITIVE "Learning Moment" debrief shown when an
 * attack completes without being reported. It is never a penalty — just "here's
 * the pattern so you catch it next time".
 */
export interface MissedIncidentDebrief {
  /** What the attack was (the incident / story title). */
  title: string;
  /** MITRE technique ID(s) the attack used. */
  techniques: string[];
  /** One-line "how you could have caught it" tell — the standout signal. */
  tell: string;
}

// Display enrichment + feed helpers live in ./liveEventEnrich (no engine import —
// the team room uses enrichEvent without pulling the simulation's answer data).
import {
  enrichEvent, applyUserVariant, buildRuleId, extractDomainUsers, injectAdvancedFidelityNoise, isOnceOnly, jitteredOffset, severityBase, shuffleArray,
  type LiveEvent,
} from "./liveEventEnrich";
export { enrichEvent };
export type { LiveEvent };

/**
 * SIEM correlation mirror of an EDR detection. Real SOCs forward EDR alerts into
 * the SIEM, so an analyst working the SIEM feed sees the EDR verdict as its own
 * log line — not only in the /edr console. Generated at stream time (never a
 * static feed event) so it can't disturb the positional attack-chain split.
 *
 * Deliberately emitted at MEDIUM severity: the paired EDR event remains the
 * high/critical, gradeable primary detection, while this is a corroboration log.
 * Because the grader's feedAttackEvents gate is severity high|critical, a medium
 * mirror is never counted as a second attack (no ground-truth / indicator / catch
 * inflation) — but it IS part of the serialized evidence, so a student who cites
 * the SIEM alert's host/technique is validated as citing real evidence. FP decoys
 * are not mirrored (they drive their own IT-verify training on the primary).
 */
function siemMirror(e: LiveEvent, index: number): LiveEvent | null {
  if (e.source !== "edr") return null;
  const isDetection =
    e.is_detection === true ||
    e.event_type === "av_detection" ||
    e.event_type === "edr_alert" ||
    ((e.severity === "high" || e.severity === "critical") && !!e.mitre_technique);
  if (!isDetection) return null;
  if (e.it_verify_result || e.fp_explanation || e.expected_verdict === "fp") return null;

  const vendor = e.vendor ?? "EDR";
  const host = e.hostname ? ` on ${e.hostname}` : "";
  const tech = e.mitre_technique ? ` (${e.mitre_technique})` : "";
  const desc = `SIEM correlation: ${vendor} detection ingested${host} — ${e.description ?? "malicious activity"}${tech}`;
  const mirror: LiveEvent = {
    ...e,
    id: `${e.id}__siem`,
    source: "siem",
    vendor: "Microsoft Sentinel",
    event_type: "edr_alert",
    severity: "medium",
    is_detection: undefined,
    edr_scope: undefined,
    // Drop the top-level technique/tactic so the mirror is NOT mapped to a
    // kill-chain stage in AttackChainBoard (it would otherwise duplicate the
    // EDR event's card). The technique is still shown to the analyst via
    // raw["threat.technique.id"] below.
    mitre_technique: undefined,
    mitre_tactic: undefined,
    description: desc,
    raw: {
      "AlertName": "EDR Detection — forwarded to SIEM",
      "alert.rule.id": "SIEM-EDR-FWD-001",
      "alert.severity": e.severity ?? "high",
      ...(e.hostname ? { "host.name": e.hostname } : {}),
      ...(e.src_ip ? { "host.ip": e.src_ip } : {}),
      ...(e.user_email ? { "target.user.name": e.user_email } : {}),
      ...(e.mitre_technique ? { "threat.technique.id": e.mitre_technique } : {}),
      "ExtendedProperties.Source EDR Vendor": vendor,
      "ExtendedProperties.Original Detection": e.description ?? "",
      "event.action": "edr-alert-forwarded",
      "event.outcome": "alerted",
    },
    ruleLevel: severityBase("medium"),
    ruleId: buildRuleId({ ...e, source: "siem", event_type: "edr_alert", severity: "medium" } as TelemetryEvent, index),
    displayDescription: desc,
  };
  return mirror;
}

export interface DashboardSessionRecord {
  type: "dashboard";
  date: string;
  xpEarned: number;
  /**
   * % of presented attacks the student actually caught (via a passing
   * incident report) before the SLA expired. Real signal — derived from
   * attacksCaughtCount/attacksPresentedCount, both driven by markCaught()
   * and incident-open, not by the removed per-event classify() UI.
   */
  detectRate: number;
  /** False-negative count — attacks the SLA timer expired on before the student
   * caught them. Tracked separately from detectRate on purpose (see
   * ANALYST_TELEMETRY_PLAN.md) — over-escalating and missing real attacks are
   * opposite failure modes and averaging them hides both. Optional: records
   * saved before this field lack it. */
  fnCount?: number;
  avgCatchMs: number | null;
  attacksCaughtCount: number;
  attacksPresentedCount: number;
  /** Rows opened this session — a coarse thoroughness signal. Optional: records
   * saved before this field lack it. */
  eventsOpenedCount?: number;
  /** Wall-clock session length in ms (records saved before this field lack it) */
  durationMs?: number;
}

// ─── Hook ─────────────────────────────────────────────────────────────────────

interface UseLiveEventsOptions {
  eventPool?: TelemetryEvent[];    // legacy mode: benign background noise
  companyId?: string;              // engine mode: generate events algorithmically
  /** The session's attack story — events injected IN ORDER in small phases */
  story?: AttackStory | null;
  /** Called when the active story's final phase has been injected */
  onStoryComplete?: () => void;
  /** True while the analyst is actively investigating this incident (report modal
   *  open, or the EDR console in play). When true, the "you missed it" verdict is
   *  deferred — a thorough investigation must never auto-fail the analyst. */
  isInvestigating?: () => boolean;
  intervalMs?: number;
  maxVisible?: number;
  /**
   * When false, the feed starts IDLE — no initial events, no streaming — until
   * reset()/resume() is called. The dashboard uses this so nothing runs until
   * the student presses Start Training. Defaults to true (legacy auto-start).
   */
  autoStart?: boolean;
}

export interface LiveEventsApi {
  events: LiveEvent[];
  isStreaming: boolean;
  sessionXp: number;
  newIds: Set<string>;              // IDs of the most recent batch (for fade-in animation)
  activeIncident: ActiveIncident | null;
  dismissIncident: () => void;
  pause: () => void;
  resume: () => void;
  reset: (pool?: TelemetryEvent[], story?: AttackStory | null) => void;
  /** Arm a new attack story mid-session. Optional delayMs overrides the default
   *  8-12 min campaign cooldown (the dashboard uses a shorter gap after a report). */
  startStory: (story: AttackStory, delayMs?: number) => void;
  // Fires when an attack completes uncaught — drives the POSITIVE "Learning
  // Moment" debrief (NOT a fail: no XP loss, no permanent halt). Paired with the
  // missedIncident teaching payload. clearMissedAttack resets both.
  missedAttack: boolean;
  clearMissedAttack: () => void;
  /** Teaching payload for the Learning-Moment debrief (what the attack was, its
   *  MITRE technique(s), and the tell) — null when no debrief is active. */
  missedIncident: MissedIncidentDebrief | null;
  /** Register a real catch — called when the student's incident report passes.
   * Stops the response clock and records catch speed + response time. */
  markCaught: (eventId: string) => void;
  // Response clock — ELAPSED seconds since the attack's first phase (counts UP;
  // pauses while investigating). null when no active attack. Never a deadline.
  attackTimerSeconds: number | null;
  /** Response time (ms) for the most recently handled incident, from attack
   * first-phase injection to catch / passing report. null until one is handled.
   * A coaching metric only — never affects pass/fail or score. */
  lastResponseMs: number | null;
  /** The response-time TARGET in seconds (a coaching benchmark, not a deadline). */
  responseTargetSeconds: number;
  fnCount: number;
  // Phase-1 behavioral telemetry (ANALYST_TELEMETRY_PLAN.md)
  eventsOpenedCount: number;
  recordEventOpened: () => void;
  attacksCaughtCount: number;
  avgCatchMs: number | null;
  endSession: () => DashboardSessionRecord;
  // Attack chain reconstruction (populated after student catches an attack)
  lastAttackChain: LiveEvent[] | null;
  clearLastAttackChain: () => void;
  /** Award bonus XP not tied to a specific event classification (e.g. worksheet, notes grading) */
  addXp: (xp: number) => void;
}

// ─── Learning-Moment debrief builders ─────────────────────────────────────────

/** The standout signal an analyst could have caught the attack by — the highest-
 *  severity event's plain-language description, which reads as the "tell". */
function buildMissedTell(events: TelemetryEvent[]): string {
  const key = events.find(e => e.severity === "critical")
           ?? events.find(e => e.severity === "high")
           ?? events[0];
  const desc = key?.description?.trim();
  if (desc && desc.length > 8) return desc;
  return "an unusual burst of high-severity activity from a single source, out of step with the normal baseline";
}

/** Assemble the positive teaching payload shown when an attack completes uncaught. */
function buildMissedDebrief(title: string, techniques: string[], events: TelemetryEvent[]): MissedIncidentDebrief {
  return {
    title: title || "A multi-stage attack",
    techniques: Array.from(new Set(techniques.filter(Boolean))),
    tell: buildMissedTell(events),
  };
}

// Incident title generator from attack event descriptions
function inferIncidentTitle(events: TelemetryEvent[]): string {
  const highSev = events.find(e => e.severity === "critical" || e.severity === "high");
  if (!highSev) return "Suspicious Activity Detected";
  const desc = highSev.description ?? "";
  // Derive a short title from the description
  if (/cobalt|beacon|c2/i.test(desc))      return "Active C2 Beaconing Detected";
  if (/ransomware|encrypt|locked/i.test(desc)) return "Ransomware Activity Detected";
  if (/lsass|credential|mimikatz|dcsync/i.test(desc)) return "Credential Theft in Progress";
  if (/psexec|lateral|smb|wmi/i.test(desc)) return "Lateral Movement Detected";
  if (/phish|invoice|macro/i.test(desc))   return "Phishing Attack — Active Infection";
  if (/powershell|encoded|base64/i.test(desc)) return "Malicious PowerShell Execution";
  if (/oauth|consent|graph api/i.test(desc)) return "Unauthorized Cloud Access";
  if (/exfil|upload|download.*bulk/i.test(desc)) return "Data Exfiltration Attempt";
  return "High-Severity Incident — Investigate";
}

// Convert GeneratedEvent (engine output) → TelemetryEvent for enrichEvent()
function generatedToTelemetry(g: GeneratedEvent, idx: number): TelemetryEvent {
  return {
    ...g,
    id:  g.id  ?? `eng_${Date.now()}_${idx}`,
    ts:  g.ts  ?? new Date().toISOString(),
    severity: g.severity ?? "informational",
  } as TelemetryEvent;
}

export function useLiveEvents({
  eventPool = [],
  companyId,
  story = null,
  onStoryComplete,
  isInvestigating,
  intervalMs = 40000,
  maxVisible = 100,
  autoStart = true,
}: UseLiveEventsOptions): LiveEventsApi {
  // Engine mode: true when companyId is provided
  const engineMode = Boolean(companyId);
  // Start empty — populated in useEffect so SSR and client render the same HTML (avoids hydration mismatch)
  const [events, setEvents] = useState<LiveEvent[]>([]);
  const [isStreaming, setIsStreaming]       = useState(autoStart);
  // Read by timers/intervals (P5-02/03): they outlive renders, so they check the
  // live value instead of a captured one.
  const isStreamingRef = useRef(autoStart);
  isStreamingRef.current = isStreaming;
  const [sessionXp, setSessionXp]           = useState(0);
  const [newIds, setNewIds]                 = useState<Set<string>>(new Set());
  const [activeIncident, setActiveIncident] = useState<ActiveIncident | null>(null);
  const [missedAttack, setMissedAttack]     = useState(false);
  // Teaching payload for the positive "Learning Moment" debrief (what the attack
  // was), captured when an uncaught attack completes. null when no debrief.
  const [missedIncident, setMissedIncident] = useState<MissedIncidentDebrief | null>(null);

  // SLA countdown + per-skill tracking
  const [attackTimerSeconds,   setAttackTimerSeconds]   = useState<number | null>(null);
  // fnCount = missed-attack count (Phase 1 telemetry — see ANALYST_TELEMETRY_PLAN.md).
  // `missedAttack` stays a one-shot boolean for the existing "you missed it" UI
  // toast; fnCount is the cumulative counter for trend reporting.
  const [fnCount,               setFnCount]              = useState(0);
  const [eventsOpenedCount,     setEventsOpenedCount]    = useState(0);
  const [attacksCaughtCount,    setAttacksCaughtCount]   = useState(0);
  // Real denominator for detectRate: every non-FP incident that ever opened
  // this session, whether it was ultimately caught or missed.
  const [attacksPresentedCount, setAttacksPresentedCount] = useState(0);
  const [avgCatchMs,           setAvgCatchMs]           = useState<number | null>(null);
  // Response time (ms) for the most recently handled incident — from attack
  // first-phase injection to the catch / passing report. Surfaced as a coaching
  // point in the incident report; never affects pass/fail or score.
  const [lastResponseMs,       setLastResponseMs]       = useState<number | null>(null);
  const [lastAttackChain,      setLastAttackChain]      = useState<LiveEvent[] | null>(null);
  /** Incident ids already counted toward attacksCaughtCount — guards markCaught
   * against double-incrementing if it's ever invoked twice for the same incident. */
  const countedIncidentIdsRef = useRef<Set<string>>(new Set());

  const poolRef           = useRef<TelemetryEvent[]>(eventPool);
  const worldStateRef     = useRef<WorldState | null>(
    companyId ? initWorldState(companyId, Date.now() & 0xFFFFFF) : null
  );
  /** Active attack story + injection cursor (events injected in order) */
  const storyRef          = useRef<AttackStory | null>(story);

  /**
   * enrichEvent + progressive fidelity. Log fidelity is a property of the
   * SESSION, not the individual event: when the active story is advanced-tier
   * (a Hard session), EVERY event — benign background noise included — gets
   * production-grade metadata noise. Applying it session-wide (not just to
   * attack events) is deliberate: if only malicious rows were "fuller", field
   * count would leak the answer. Foundation/core sessions stay clean.
   */
  const enrichWithFidelity = useCallback((e: TelemetryEvent, idx: number): LiveEvent => {
    const le = enrichEvent(e, idx);
    if (storyRef.current?.complexity === "advanced" || e.tier === "advanced") {
      injectAdvancedFidelityNoise(le.raw, le);
    }
    return le;
  }, []);
  const storyCursorRef    = useRef(0);
  const onStoryCompleteRef = useRef(onStoryComplete);
  onStoryCompleteRef.current = onStoryComplete;
  // Reassigned every render so the miss-watchdog always reads the CURRENT
  // "is the analyst investigating right now?" closure.
  const isInvestigatingRef = useRef(isInvestigating);
  isInvestigatingRef.current = isInvestigating;
  // The live feed is a low-pressure PRACTICE space. When an attack completes
  // uncaught we DO surface it — as a POSITIVE "Learning Moment" debrief, never a
  // punishment. This watchdog fires it only after a GENEROUSLY long grace (far
  // longer than the old 4-minute trap), never while the analyst is mid-
  // investigation (it re-checks on a ~60s delay instead of interrupting), and
  // never once markCaught has run. It does not fail the shift or claw back XP —
  // page.tsx pauses the feed behind the modal and resumes + arms the next attack
  // when they dismiss it.
  const MISS_DEBRIEF_GRACE_MS = 540_000; // 9 minutes after the attack's final phase
  const missWatchdogRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const scheduleDebriefCheck = useCallback((delay: number, debrief: MissedIncidentDebrief) => {
    if (missWatchdogRef.current) clearTimeout(missWatchdogRef.current);
    missWatchdogRef.current = setTimeout(() => {
      missWatchdogRef.current = null;
      if (caughtRef.current) return;                          // caught in time → no debrief
      if (isInvestigatingRef.current?.() || !isStreamingRef.current) {  // working it, or feed paused → wait, never interrupt
        scheduleDebriefCheck(60_000, debrief);
        return;
      }
      // Surface the positive Learning-Moment debrief and pause the feed so the
      // analyst actually reads it. No fail, no XP loss — page.tsx resumes on close.
      setMissedIncident(debrief);
      setMissedAttack(true);
      setIsStreaming(false);
    }, delay);
  }, []);
  const globalIdx         = useRef(15);
  const activeIncidentRef = useRef<ActiveIncident | null>(null);
  const missTimerRef      = useRef<ReturnType<typeof setTimeout> | null>(null);
  const caughtRef         = useRef(false);
  const attackTimerRef    = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Latest injectNextPhase — armPhase calls it without a dependency cycle. */
  const injectNextPhaseRef = useRef<(() => void) | null>(null);
  /**
   * The ONLY way to schedule the next story phase (P5-02). It always clears the
   * pending timer first, so there is never more than one phase chain — reset()
   * and startStory() used to arm a timer that the streaming effect then
   * overwrote without clearing, leaving an orphaned second chain that injected
   * at double pace and kept going while the feed was paused.
   */
  const armPhase = useCallback((delay: number) => {
    if (attackTimerRef.current) clearTimeout(attackTimerRef.current);
    attackTimerRef.current = setTimeout(() => {
      attackTimerRef.current = null;
      injectNextPhaseRef.current?.();
    }, delay);
  }, []);
  /** IDs of "once-only" events (IT-verify / FP training) already emitted this session */
  const seenOnceRef        = useRef<Set<string>>(new Set());
  /** Shuffle deck — repeatable events in random order, no duplicates until full cycle */
  const deckRef            = useRef<TelemetryEvent[]>([]);
  const deckPosRef         = useRef(0);
  /** How many times the deck has been fully cycled through — used for user-rotation variants */
  const cycleCountRef      = useRef(0);
  /** Pool of regular user emails extracted from the event pool for rotation */
  const domainUsersRef     = useRef<string[]>([]);
  /** SLA countdown interval + catch speed tracking */
  const slaIntervalRef     = useRef<ReturnType<typeof setInterval> | null>(null);
  const catchSpeedMsRef    = useRef<number[]>([]);
  const attackInjectedAtRef = useRef<number | null>(null);
  /** Session start — reset() restarts it; endSession() reports the duration */
  const sessionStartRef    = useRef(Date.now());

  /** Build (or rebuild) the shuffle deck from the current pool */
  const buildDeck = (pool: TelemetryEvent[]) => {
    const repeatable = pool.filter(e => !isOnceOnly(e));
    deckRef.current  = shuffleArray(repeatable);
    deckPosRef.current = 0;
  };

  /** Pull the next event from the deck — reshuffles when exhausted, applies user-rotation on repeat cycles */
  const nextFromDeck = (): TelemetryEvent | null => {
    if (deckRef.current.length === 0) return null;
    if (deckPosRef.current >= deckRef.current.length) {
      // Reshuffle for next cycle — prevents same last→first adjacency
      deckRef.current = shuffleArray(deckRef.current);
      deckPosRef.current = 0;
      cycleCountRef.current += 1;
    }
    const event = deckRef.current[deckPosRef.current++];
    // On repeat cycles, rotate the acting user so the feed never looks identical
    return cycleCountRef.current > 0
      ? applyUserVariant(event, cycleCountRef.current, domainUsersRef.current)
      : event;
  };

  // ── Populate initial events client-side only (avoids SSR/hydration mismatch) ─
  useEffect(() => {
    // Idle until Start Training: with autoStart=false the feed shows nothing
    // until reset() runs (from handleStartTraining). No logs before the shift.
    if (!autoStart) return;
    const now = Date.now();

    if (engineMode && worldStateRef.current) {
      // ENGINE MODE: generate first 15 events algorithmically
      const world = worldStateRef.current;
      const initial: TelemetryEvent[] = [];
      for (let i = 0; i < 15; i++) {
        const g = generateBenignEvent(world);
        world.simTime += world.rng.range(30_000, 120_000);
        initial.push(generatedToTelemetry(g, i));
      }
      setEvents(
        initial.map((e, i) =>
          enrichWithFidelity(withRebasedTime(e, new Date(now - jitteredOffset(14 - i)).toISOString()), i)
        ).reverse()
      );
      return;
    }

    // LEGACY MODE: shuffle from static pool
    const pool = poolRef.current;
    // Shuffle the whole pool so initial 15 events cover diverse sources, not just the first category in file order
    const shuffled = shuffleArray(pool);
    const initial = shuffled.slice(0, 15);
    initial.forEach(e => { if (isOnceOnly(e)) seenOnceRef.current.add(e.id); });
    const repeatable = shuffled.slice(15).filter(e => !isOnceOnly(e));
    deckRef.current  = shuffleArray(repeatable.length > 0 ? repeatable : pool.filter(e => !isOnceOnly(e)));
    deckPosRef.current = 0;
    domainUsersRef.current = extractDomainUsers(pool);
    setEvents(
      initial.map((e, i) =>
        enrichWithFidelity(withRebasedTime(e, new Date(now - jitteredOffset(14 - i)).toISOString()), i)
      ).reverse()
    );
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // intentionally runs once on mount only

  // ── Normal benign tick ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!isStreaming) return;
    const timer = setInterval(() => {

      // ── ENGINE MODE ────────────────────────────────────────────────────────
      if (engineMode && worldStateRef.current) {
        const world = worldStateRef.current;
        world.simTime = Date.now();

        // Fire next attack phase if due
        if (world.attack && attackDue(world)) {
          const attackEvents = advanceAttack(world);
          // advanceAttack() clears world.attack once every phase has injected —
          // that is the moment the story is genuinely over.
          const storyJustFinished = world.attack === null;
          if (attackEvents && attackEvents.length > 0) {
            const isFP = world.attack?.isFP ?? false;
            const now  = Date.now();
            const times = phaseTimes(attackEvents.length, now);
            const raw  = attackEvents.map((g: GeneratedEvent, i: number) => {
              const tele = generatedToTelemetry(g, globalIdx.current + i);
              return {
                ...tele,
                // L-02: spread the incident's events across the last minutes, not a 3-4s
                // burst — building the timeline is a real correlation exercise — and
                // never in the future (phaseTimes).
                ts: new Date(times[i]).toISOString(),
                id: `eng_atk_${now}_${i}`,
              };
            });
            globalIdx.current += raw.length;
            const enriched = raw.flatMap(ev => {
              const en = enrichWithFidelity(ev, globalIdx.current++);
              const m = siemMirror(en, globalIdx.current++);
              return m ? [en, m] : [en];
            });
            const batchIds  = new Set(enriched.map(e => e.id));

            if (!isFP) {
              const incident: ActiveIncident = {
                id: `inc_${now}`,
                title: inferIncidentTitle(raw),
                severity: raw.some(e => e.severity === "critical") ? "critical" : "high",
                injectedAt: now,
                eventIds: Array.from(batchIds),
              };
              activeIncidentRef.current = incident;
              caughtRef.current = false;
              attackInjectedAtRef.current = now;
              setAttacksPresentedCount(c => c + 1);
              // Response clock counts UP from 0 — an elapsed timer, not a
              // countdown. It is never a fail at any value; it only measures how
              // long the analyst took so the report can coach on pace.
              setAttackTimerSeconds(0);
              if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
              slaIntervalRef.current = setInterval(() => {
                // Paused while the analyst is working the case (report open / EDR
                // in play) — that time must not count against them. No fail, ever.
                if (isInvestigatingRef.current?.()) return;
                if (!isStreamingRef.current) return;   // feed paused → the clock pauses too (P5-03)
                setAttackTimerSeconds(prev => (prev === null ? null : prev + 1));
              }, 1000);
              setActiveIncident(incident);
            }

            setNewIds(batchIds);
            setEvents(prev => mergeByTime(enriched, prev, maxVisible));
            setTimeout(() => setNewIds(new Set()), 2000);

            // Completed uncaught → schedule the POSITIVE Learning-Moment debrief
            // after a generous grace. Never a fail, never a halt (page.tsx
            // resumes + arms the next attack on dismiss); a passing report before
            // then cancels it via markCaught.
            if (storyJustFinished && !isFP && !caughtRef.current) {
              const inc = activeIncidentRef.current;
              if (inc) {
                const techniques = Array.from(new Set(raw.map(e => e.mitre_technique).filter((m): m is string => !!m)));
                scheduleDebriefCheck(MISS_DEBRIEF_GRACE_MS, buildMissedDebrief(inc.title, techniques, raw));
              }
            }
          }
          return;
        }

        // Generate benign events
        const batchSize = world.rng.range(1, 2);
        const newRaw: TelemetryEvent[] = [];
        for (let i = 0; i < batchSize; i++) {
          const g = generateBenignEvent(world);
          world.simTime += world.rng.range(10_000, 40_000);
          newRaw.push(generatedToTelemetry(g, globalIdx.current + i));
        }
        globalIdx.current += newRaw.length;
        const enriched = newRaw.map(e => enrichWithFidelity(withRebasedTime(e, new Date().toISOString()), globalIdx.current++));
        const batchIds  = new Set(enriched.map(e => e.id));
        setNewIds(batchIds);
        setEvents(prev => mergeByTime(enriched, prev, maxVisible));
        setTimeout(() => setNewIds(new Set()), 1500);
        return;
      }

      // ── LEGACY MODE (shuffle deck) ─────────────────────────────────────────
      const pool = poolRef.current;
      if (pool.length === 0) return;

      const batchSize = Math.floor(Math.random() * 2) + 1;
      const newRaw: TelemetryEvent[] = [];

      for (let i = 0; i < batchSize; i++) {
        let chosen: TelemetryEvent | null = null;
        if (Math.random() < 0.10) {
          const unsentOnce = pool.filter(e => isOnceOnly(e) && !seenOnceRef.current.has(e.id));
          if (unsentOnce.length > 0) {
            chosen = unsentOnce[Math.floor(Math.random() * unsentOnce.length)];
            seenOnceRef.current.add(chosen.id);
          }
        }
        if (!chosen) chosen = nextFromDeck();
        if (!chosen) chosen = pool[Math.floor(Math.random() * pool.length)];
        newRaw.push({ ...withRebasedTime(chosen, new Date().toISOString()), id: `${chosen.id}_${Date.now()}_${i}` });
      }

      const enriched = newRaw.flatMap(ev => {
        const en = enrichWithFidelity(ev, globalIdx.current++);
        const m = siemMirror(en, globalIdx.current++);
        return m ? [en, m] : [en];
      });
      const batchIds  = new Set(enriched.map(e => e.id));
      setNewIds(batchIds);
      setEvents(prev => mergeByTime(enriched, prev, maxVisible));
      setTimeout(() => setNewIds(new Set()), 1500);
    }, intervalMs);

    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- interval keyed intentionally; enrichWithFidelity/scheduleDebriefCheck are useCallback-stable and read live values via refs, so recreating the interval on their identity would only churn it
  }, [isStreaming, intervalMs, maxVisible, engineMode]);

  // ── Attack injection — Story Scheduler ───────────────────────────────────────
  // The session story's events are injected IN ORDER in small phases (2-3 events)
  // so the student watches a coherent kill-chain unfold: first phase within
  // ~2-3 minutes, then a new phase every 2-4 minutes until all events appeared.
  const FIRST_PHASE_DELAY = () => 120_000 + Math.floor(Math.random() * 60_000);   // 2-3 min
  const PHASE_GAP         = () => 120_000 + Math.floor(Math.random() * 120_000);  // 2-4 min

  // Response-time TARGET — a coaching benchmark, NOT a deadline. The response
  // clock counts up from 0; if the analyst catches/reports within this many
  // seconds the report notes a good pace, otherwise it gently flags faster
  // triage as an improvement area. Nothing fails or halts at this value.
  const SLA_SECONDS = 900; // 15 minutes — response-time target

  /**
   * Quiet period between the END of one attack campaign and the FIRST phase of
   * the next. Widened from 4-6 to 8-12 minutes: back-to-back campaigns left no
   * room to finish investigating and writing up one incident before the next
   * started competing for attention, which reads as relentless rather than
   * realistic — a real shift has long quiet stretches between incidents.
   */
  const ATTACK_COOLDOWN = () => 480_000 + Math.floor(Math.random() * 240_000); // 8-12 min

  const injectNextPhase = useCallback(() => {
    const s = storyRef.current;
    if (!s) return;
    const cursor = storyCursorRef.current;
    if (cursor >= s.events.length) return;
    // Never inject behind a paused feed (report open, debrief, manual pause) —
    // check again shortly; resume continues the story where it stopped.
    if (!isStreamingRef.current) { armPhase(5_000); return; }

    const isFirstPhase = cursor === 0;
    const n = Math.min(s.events.length - cursor, 2 + (Math.random() < 0.5 ? 1 : 0)); // 2-3 events
    const now = Date.now();
    const times = phaseTimes(n, now);
    const slice = s.events.slice(cursor, cursor + n).map((e, i) => ({
      // L-02: spread over the last minute or two in story order (was a 4s burst), so
      // the attack doesn't stand out as "the only thing off the 60s grid" — and never
      // stamped in the future (phaseTimes).
      ...withRebasedTime(e, new Date(times[i]).toISOString(), { storyClock: "local" }),
      id: `atk_${e.id}_${now}_${i}`,
    }));
    storyCursorRef.current = cursor + n;

    const enriched = slice.flatMap(ev => {
      const en = enrichWithFidelity(ev, globalIdx.current++);
      const m = siemMirror(en, globalIdx.current++);
      return m ? [en, m] : [en];
    });
    const batchIds = new Set(enriched.map(e => e.id));

    if (isFirstPhase) {
      // Open the incident: SLA countdown + miss detection fire once per story
      const incident: ActiveIncident = {
        id: `inc_${now}`, title: s.title,
        severity: slice.some(e => e.severity === "critical") ? "critical" : "high",
        injectedAt: now, eventIds: Array.from(batchIds),
      };
      activeIncidentRef.current = incident;
      caughtRef.current = false;
      attackInjectedAtRef.current = now;
      setAttacksPresentedCount(c => c + 1);
      // Response clock starts at 0 and counts UP — an elapsed timer measuring how
      // long the analyst takes to respond. It never fails or halts at any value.
      setAttackTimerSeconds(0);
      if (slaIntervalRef.current) clearInterval(slaIntervalRef.current);
      slaIntervalRef.current = setInterval(() => {
        // Pause the response clock while the analyst is working the case — the
        // report is open (they're pulling data into it) or the EDR console is in
        // play. That time must not count against them.
        if (isInvestigatingRef.current?.()) return;
        if (!isStreamingRef.current) return;   // feed paused → the clock pauses too (P5-03)
        setAttackTimerSeconds(prev => (prev === null ? null : prev + 1));
      }, 1000);
      setActiveIncident(incident);
    } else if (activeIncidentRef.current) {
      // Later phases extend the same incident (chain board sees the full story)
      activeIncidentRef.current = {
        ...activeIncidentRef.current,
        eventIds: [...activeIncidentRef.current.eventIds, ...batchIds],
      };
      setActiveIncident(activeIncidentRef.current);
    }

    setNewIds(batchIds);
    setEvents(prev => mergeByTime(enriched, prev, maxVisible));
    setTimeout(() => setNewIds(new Set()), 2000);

    if (storyCursorRef.current >= s.events.length) {
      // Story fully injected. If it was never caught, schedule the POSITIVE
      // Learning-Moment debrief after a generous grace — never a fail, never a
      // permanent halt (page.tsx pauses the feed behind the modal, then resumes
      // and arms the next attack on dismiss). A passing report before the grace
      // elapses cancels it via markCaught.
      if (!caughtRef.current) {
        scheduleDebriefCheck(MISS_DEBRIEF_GRACE_MS, buildMissedDebrief(s.title, s.mitre ?? [], s.events));
      }
      storyRef.current = null;
      onStoryCompleteRef.current?.();
    } else {
      armPhase(PHASE_GAP());
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [maxVisible]);
  injectNextPhaseRef.current = injectNextPhase;

  useEffect(() => {
    if (!isStreaming) return;

    if (engineMode && worldStateRef.current) {
      // ENGINE MODE: pick a playbook and arm it; the benign tick fires phases
      const engineDelay = () => Math.floor(Math.random() * 60_000) + 540_000;
      const scheduleEngineAttack = () => {
        const world = worldStateRef.current!;
        startAttack(world, pickPlaybook(world));
        attackTimerRef.current = setTimeout(scheduleEngineAttack, engineDelay());
      };
      attackTimerRef.current = setTimeout(scheduleEngineAttack, engineDelay());
    } else if (!attackTimerRef.current) {
      // STORY MODE: arm the first phase — unless reset()/startStory() already
      // queued one with its own delay (kept, not doubled: P5-02).
      armPhase(FIRST_PHASE_DELAY());
    }

    return () => {
      // Pausing stops the phase chain only. The response clock and the missed-
      // attack debrief survive a pause (they wait while paused) — destroying
      // them here froze the clock and could stall the shift for good (P5-03).
      if (attackTimerRef.current) { clearTimeout(attackTimerRef.current); attackTimerRef.current = null; }
      if (missTimerRef.current)   clearTimeout(missTimerRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isStreaming, maxVisible, engineMode, injectNextPhase]);

  /** Arm a new story mid-session (second attack after the first completes) */
  const startStory = useCallback((next: AttackStory, delayMs?: number) => {
    storyRef.current = next;
    storyCursorRef.current = 0;
    armPhase(delayMs ?? ATTACK_COOLDOWN());
  }, [armPhase]);

  // Everything is torn down on unmount (the streaming effect above only stops
  // the phase chain on pause).
  useEffect(() => () => {
    if (attackTimerRef.current)  clearTimeout(attackTimerRef.current);
    if (missTimerRef.current)    clearTimeout(missTimerRef.current);
    if (missWatchdogRef.current) clearTimeout(missWatchdogRef.current);
    if (slaIntervalRef.current)  clearInterval(slaIntervalRef.current);
  }, []);

  const pause = useCallback(() => setIsStreaming(false), []);
  const resume = useCallback(() => setIsStreaming(true), []);

  const dismissIncident = useCallback(() => {
    setActiveIncident(null);
    activeIncidentRef.current = null;
  }, []);

  const clearMissedAttack = useCallback(() => { setMissedAttack(false); setMissedIncident(null); }, []);

  const clearLastAttackChain = useCallback(() => setLastAttackChain(null), []);

  const markCaught = useCallback((eventId: string) => {
    const incident = activeIncidentRef.current;
    if (!incident) return;
    if (incident.eventIds.includes(eventId)) {
      caughtRef.current = true;
      if (missTimerRef.current) {
        clearTimeout(missTimerRef.current);
        missTimerRef.current = null;
      }
      // A catch during the post-last-phase grace cancels the "missed" verdict.
      if (missWatchdogRef.current) { clearTimeout(missWatchdogRef.current); missWatchdogRef.current = null; }
      // Record catch speed + response time, then stop the response clock.
      if (attackInjectedAtRef.current !== null) {
        const elapsed = Date.now() - attackInjectedAtRef.current;
        catchSpeedMsRef.current.push(elapsed);
        attackInjectedAtRef.current = null;
        const all = catchSpeedMsRef.current;
        setAvgCatchMs(Math.round(all.reduce((a, b) => a + b, 0) / all.length));
        // This incident's response time — the coaching metric shown in the report.
        setLastResponseMs(elapsed);
      }
      // Count once per incident — guards against a double-call for the same catch.
      if (!countedIncidentIdsRef.current.has(incident.id)) {
        countedIncidentIdsRef.current.add(incident.id);
        setAttacksCaughtCount(c => c + 1);
      }
      if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
      setAttackTimerSeconds(null);
      // Capture the chain events for AttackChainBoard
      setEvents(current => {
        const chainEvents = current.filter(e => incident.eventIds.includes(e.id));
        if (chainEvents.length > 0) setLastAttackChain(chainEvents);
        return current;
      });
    }
  }, []);

  const reset = useCallback((pool?: TelemetryEvent[], newStory?: AttackStory | null) => {
    if (pool) poolRef.current = pool;
    // Clear pending timers
    if (attackTimerRef.current) { clearTimeout(attackTimerRef.current); attackTimerRef.current = null; }
    if (missTimerRef.current)   { clearTimeout(missTimerRef.current);   missTimerRef.current   = null; }
    if (missWatchdogRef.current){ clearTimeout(missWatchdogRef.current);missWatchdogRef.current = null; }
    // Arm the new session story (or keep the current one when omitted)
    if (newStory !== undefined) {
      storyRef.current = newStory;
      storyCursorRef.current = 0;
    }
    if (storyRef.current) {
      armPhase(120_000 + Math.floor(Math.random() * 60_000));
    }
    globalIdx.current = 15;
    activeIncidentRef.current = null;
    caughtRef.current = false;
    seenOnceRef.current = new Set(); // reset once-only tracking on company/pool switch
    const src = pool ?? poolRef.current;
    // Rebuild shuffle deck for the new pool (shuffled so initial 15 cover diverse sources)
    const srcShuffled = shuffleArray(src);
    buildDeck(srcShuffled);
    const now = Date.now();
    setEvents(srcShuffled.slice(0, 15).map((e, i) =>
      enrichWithFidelity(withRebasedTime(e, new Date(now - (14 - i) * 60_000).toISOString()), i)
    ).reverse());
    setSessionXp(0);
    setActiveIncident(null);
    setMissedAttack(false);
    setMissedIncident(null);
    setIsStreaming(true);
    setFnCount(0);
    setEventsOpenedCount(0);
    setAttacksCaughtCount(0);
    setAttacksPresentedCount(0);
    setAvgCatchMs(null);
    setLastResponseMs(null);
    setAttackTimerSeconds(null);
    setLastAttackChain(null);
    catchSpeedMsRef.current    = [];
    countedIncidentIdsRef.current = new Set();
    attackInjectedAtRef.current = null;
    sessionStartRef.current    = Date.now();
    if (slaIntervalRef.current) { clearInterval(slaIntervalRef.current); slaIntervalRef.current = null; }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const endSession = useCallback((): DashboardSessionRecord => {
    const record: DashboardSessionRecord = {
      type: "dashboard",
      date: new Date().toISOString(),
      xpEarned: sessionXp,
      detectRate: attacksPresentedCount > 0 ? Math.round((attacksCaughtCount / attacksPresentedCount) * 100) : 0,
      fnCount,
      avgCatchMs,
      attacksCaughtCount,
      attacksPresentedCount,
      eventsOpenedCount,
      durationMs: Date.now() - sessionStartRef.current,
    };
    // Persist through the storage facade → DB `dashboard_sessions` for signed-in
    // users, localStorage for guests (same "soc_dashboard_sessions" key). Uncapped
    // on purpose: remoteBackend's insert diff needs the array strictly append-only,
    // so a slice cap would silently drop DB inserts past it (persistence-migration
    // Stage 2). The backend is SSR-safe, so no window guard is needed.
    appendDashboardSession(record, Number.MAX_SAFE_INTEGER);
    return record;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionXp, fnCount, attacksCaughtCount, attacksPresentedCount, eventsOpenedCount, avgCatchMs]);

  const addXp = useCallback((xp: number) => {
    if (xp !== 0) setSessionXp(x => Math.max(0, x + xp));
  }, []);

  // Phase-1 telemetry (see ANALYST_TELEMETRY_PLAN.md): a simple running count
  // of distinct rows the student opened this session, before/around reaching
  // their verdict. Session-scoped rather than tightly bound to one incident —
  // per-incident scoping is a Phase 2 refinement.
  const recordEventOpened = useCallback(() => {
    setEventsOpenedCount(c => c + 1);
  }, []);

  return {
    events, isStreaming, sessionXp,
    newIds, activeIncident, dismissIncident, pause, resume, reset, startStory,
    missedAttack, missedIncident, clearMissedAttack, markCaught,
    attackTimerSeconds, lastResponseMs, responseTargetSeconds: SLA_SECONDS,
    fnCount, eventsOpenedCount, recordEventOpened,
    attacksCaughtCount, avgCatchMs, endSession,
    lastAttackChain, clearLastAttackChain, addXp,
  };
}
