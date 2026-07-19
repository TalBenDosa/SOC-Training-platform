"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import { pickStoryForCompany, instantiateStory } from "./attackStories";
import type { AttackStory } from "./attackStories";
import { Topbar } from "@/components/nav/Topbar";
import { Card, StatCard } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { useLiveEvents } from "./useLiveEvents";
import type { LiveEvent } from "./useLiveEvents";
import { EventFeed } from "./EventFeed";
import { addTotalXp } from "@/lib/storage/progress";
import { WorkflowGuide } from "./WorkflowGuide";
import { BENIGN_EVENTS } from "./benignEvents";
import { SiemStats } from "./SiemStats";
import { CompanySelector } from "./CompanySelector";
import { SessionSummaryModal } from "./SessionSummaryModal";
import type { DashboardSessionRecord } from "./useLiveEvents";
import { IncidentReportModal } from "./IncidentReportModal";
import { AttackChainBoard } from "./AttackChainBoard";
import { CompanyClearedModal } from "./CompanyClearedModal";
import { startDashboardTour } from "./OnboardingTour";
import { COMPANY_PROFILES, COMPANY_EVENTS, NEXACORP_PROFILE } from "@/lib/sim/companyProfiles";
import {
  AlertTriangle, BookOpen, Building2, FileText, Filter, LogOut, Pause, Play,
  RefreshCw, Search, Siren, Star, Target, X, Zap,
} from "lucide-react";

const COMPANY_KEY       = "soc_selected_company_v1";
const UNLOCKED_KEY      = "soc_company_progress_v1";
const CLEARED_KEY       = "soc_company_cleared_v1";
const COMPANY_ORDER     = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];

type SessionRecord = import("./useLiveEvents").DashboardSessionRecord;

// The analyst's ONE deliverable per company: a passing incident report. It
// already grades attack identification + evidence + action + impact holistically
// (see /api/dashboard/incident-report), so there's no separate "classify N
// events" gate — that would just be a second, redundant scoring mechanism.
interface ObjDef { label: string; met: (r: SessionRecord, reportPassed: boolean) => boolean }
const REPORT_OBJECTIVE: ObjDef[] = [
  { label: "Submit a passing incident report (score ≥ 60)", met: (_, rp) => rp },
];
const COMPANY_OBJECTIVES: Record<string, ObjDef[]> = {
  nexacorp: REPORT_OBJECTIVE, rocketstack: REPORT_OBJECTIVE, medcore: REPORT_OBJECTIVE,
  globallogis: REPORT_OBJECTIVE, quantumbank: REPORT_OBJECTIVE,
};

// ─── Event pools (computed once at module level) ──────────────────────────────

// Background noise — NexaCorp default (other companies use COMPANY_EVENTS)
// DNS events are excluded from the live feed — too noisy, not actionable in a SIEM dashboard
const ALL_EVENTS = BENIGN_EVENTS.filter(e => e.source !== "dns");

/**
 * Pull the real indicator values (IPs, users, hosts, domains, hashes) out of a
 * set of attack events. These are the ground truth the report grader checks the
 * student's write-up against — both to reward citing real evidence and to flag
 * fabricated data (values that never appear in the actual logs).
 */
function extractIndicators(events: import("@/lib/sim/types").TelemetryEvent[]): string[] {
  const out = new Set<string>();
  for (const e of events) {
    if (e.src_ip)    out.add(e.src_ip);
    if (e.dst_ip)    out.add(e.dst_ip);
    if (e.user_email) out.add(e.user_email);
    if (e.hostname)  out.add(e.hostname);
    const dom = (e.network as { domain?: string } | undefined)?.domain;
    if (dom) out.add(dom);
    const sha = (e.file as { sha256?: string } | undefined)?.sha256;
    if (sha) out.add(sha);
    const proc = (e.process as { name?: string } | undefined)?.name;
    if (proc) out.add(proc);
  }
  return Array.from(out);
}

// ─── Source filter options ─────────────────────────────────────────────────────

const SOURCES = [
  { value: "all",        label: "All Sources" },
  { value: "edr",        label: "EDR" },
  { value: "ad",         label: "Active Directory" },
  { value: "o365",       label: "Office 365" },
  { value: "gws",        label: "Google Workspace" },
  { value: "okta",       label: "Okta" },
  { value: "firewall",   label: "Firewall" },
  { value: "dns",        label: "DNS" },
  { value: "cloudtrail", label: "Cloud Trail" },
  { value: "vpn",        label: "VPN" },
  { value: "sysmon",     label: "Sysmon" },
  { value: "proxy",      label: "Proxy" },
];

// ─── SOC Welcome / Briefing modal ────────────────────────────────────────────

const WELCOME_KEY = "soc_welcome_seen_v1";

/**
 * The single onboarding entry point for the dashboard. The 10-step SIEM tour is
 * offered here as a CHOICE rather than auto-opening on a timer — previously both
 * appeared at once (two stacked dark overlays, 13 screens before the analyst
 * could touch anything), which is what made onboarding feel cluttered.
 */
function SOCWelcomeModal({ onStart, onTakeTour }: { onStart: () => void; onTakeTour: () => void }) {
  return (
    // Overlay is fixed and scrollable so the card never pushes the page (no jump).
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-black/80 p-4 py-[7vh] backdrop-blur-sm">
      {/* Card is capped at viewport height and scrolls internally if needed. */}
      <div className="relative w-full max-w-[30rem] max-h-[86vh] overflow-y-auto rounded-2xl border border-border bg-bg-elevated shadow-2xl shadow-black/60">

        {/* Top accent bar */}
        <div className="sticky top-0 z-10 h-[3px] w-full bg-gradient-to-r from-cyber-500 via-neon-purple to-severity-critical" />

        <div className="px-7 pb-7 pt-6">
          {/* Header */}
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-cyber-500/15 border border-cyber-500/30">
              <Siren className="h-5 w-5 text-cyber-300" />
            </span>
            <div className="min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyber-500">Shift briefing</p>
              <h2 className="text-[17px] font-bold leading-tight text-white">You&apos;re the SOC analyst on shift</h2>
            </div>
          </div>

          {/* Mission — the one thing that must land */}
          <p className="mt-5 text-[13px] leading-relaxed text-slate-300">
            Security events are streaming in below. <span className="font-semibold text-white">Most are normal.</span> A real
            attack is hidden among them — <span className="font-semibold text-white">find it and report it.</span>
          </p>

          {/* 3 steps — flat list, no nested boxes, scannable at a glance */}
          <ol className="mt-5 space-y-3.5">
            {[
              { n: "1", title: "Watch the feed", body: "Click any row to open its full raw log." },
              { n: "2", title: "Investigate yourself", body: "There's no “is this bad?” button — read the evidence and decide." },
              { n: "3", title: "Report the incident", body: "Press Report Incident and write what happened. The report is graded." },
            ].map(({ n, title, body }) => (
              <li key={n} className="flex gap-3">
                <span className="mt-px flex h-[22px] w-[22px] shrink-0 items-center justify-center rounded-full border border-cyber-500/40 bg-cyber-500/15 font-mono text-[11px] font-bold text-cyber-300">
                  {n}
                </span>
                <div className="min-w-0">
                  <p className="text-[13px] font-semibold leading-snug text-white">{title}</p>
                  <p className="mt-0.5 text-[12px] leading-relaxed text-slate-400">{body}</p>
                </div>
              </li>
            ))}
          </ol>

          {/* Severity legend — the one visual cue worth learning up front */}
          <div className="mt-5 flex flex-wrap items-center gap-x-4 gap-y-2 rounded-lg border border-border/50 bg-bg/50 px-4 py-3">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">Severity</span>
            {[
              { v: "1", label: "1–3 routine",    cls: "border-slate-500/50 bg-slate-600/50 text-slate-300" },
              { v: "5", label: "4–6 look closer", cls: "border-severity-medium/80 bg-severity-medium/70 text-white" },
              { v: "9", label: "7–10 act now",    cls: "border-severity-critical bg-severity-critical text-white" },
            ].map(({ v, label, cls }) => (
              <span key={v} className="flex items-center gap-1.5 text-[12px] text-slate-300">
                <span className={cn("inline-flex h-5 w-5 items-center justify-center rounded border font-mono text-[10px] font-bold", cls)}>{v}</span>
                {label}
              </span>
            ))}
          </div>

          {/* CTAs — start now, or take the guided tour first */}
          <div className="mt-6 flex flex-col-reverse gap-2 sm:flex-row sm:items-center sm:justify-between">
            <button
              onClick={onTakeTour}
              className="rounded-lg border border-border-strong px-4 py-2.5 text-[13px] font-semibold text-slate-300 transition hover:border-cyber-500/50 hover:text-white"
            >
              Take the guided tour
            </button>
            <button
              onClick={onStart}
              className="flex items-center justify-center gap-2 rounded-lg bg-cyber-500 px-6 py-2.5 text-[13px] font-bold text-bg shadow transition hover:bg-cyber-400"
            >
              <Zap className="h-4 w-4" />
              Start my shift
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Start Training modal ─────────────────────────────────────────────────────

export type Difficulty = "easy" | "medium" | "hard";

// Difficulty describes only the CHALLENGE — never which attack is coming.
// The attack type is chosen at random and kept hidden; the analyst must find it.
const DIFFICULTIES: { id: Difficulty; label: string; blurb: string; accent: string }[] = [
  { id: "easy",   label: "Easy",   blurb: "A calmer feed with a clearer attack and a generous window to spot it.", accent: "text-neon-green" },
  { id: "medium", label: "Medium", blurb: "A busier feed. The attack blends into normal activity — read carefully.", accent: "text-severity-medium" },
  { id: "hard",   label: "Hard",   blurb: "Heavy noise, a subtle attack, and a tight window. For confident analysts.", accent: "text-severity-critical" },
];

function StartTrainingModal({
  onStart,
  onClose,
}: {
  onStart: (difficulty: Difficulty) => void;
  onClose: () => void;
}) {
  // Default new analysts to Easy — foundation-tier single-host attacks are the
  // right first practical. Students can step up to Medium/Hard themselves.
  const [selected, setSelected] = useState<Difficulty>("easy");

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg/80 backdrop-blur-sm">
      <div className="w-full max-w-lg rounded-xl border border-border bg-bg-elevated p-6 shadow-2xl">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-bold text-white">Start Training Session</h2>
          <button onClick={onClose} className="rounded p-1 text-slate-400 hover:text-white">
            <X className="h-5 w-5" />
          </button>
        </div>

        <p className="mt-2 text-sm text-slate-400">
          Pick a difficulty. A fresh session begins with normal activity — and somewhere in it, an attack.
          You won&apos;t be told what it is: watch the feed, spot it, and report it.
        </p>

        <div className="mt-5 space-y-3">
          {DIFFICULTIES.map((d) => (
            <button
              key={d.id}
              onClick={() => setSelected(d.id)}
              className={cn(
                "w-full rounded-lg border p-4 text-left transition",
                selected === d.id
                  ? "border-cyber-500/60 bg-cyber-500/10"
                  : "border-border bg-bg hover:border-border-strong"
              )}
            >
              <span className={cn("font-semibold", selected === d.id ? "text-white" : d.accent)}>{d.label}</span>
              <p className="mt-1 text-xs text-slate-400">{d.blurb}</p>
            </button>
          ))}
        </div>

        <div className="mt-6 flex justify-end gap-3">
          <Button variant="secondary" size="sm" onClick={onClose}>Cancel</Button>
          <Button variant="primary" size="sm" onClick={() => { onStart(selected); onClose(); }}>
            <Zap className="h-4 w-4" /> Start Session
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Dashboard page ───────────────────────────────────────────────────────────

// Helper: get event pool for a given company id — DNS always excluded from live feed
function getCompanyEvents(id: string) {
  if (id === "nexacorp") return BENIGN_EVENTS.filter(e => e.source !== "dns");
  const pool = COMPANY_EVENTS[id] ?? BENIGN_EVENTS;
  return pool.filter(e => e.source !== "dns");
}

function getCompanyProfile(id: string) {
  return COMPANY_PROFILES.find(c => c.id === id) ?? { ...NEXACORP_PROFILE };
}

/** Returns the source filter options relevant for the given company. */
function getSourcesForCompany(id: string): { value: string; label: string }[] {
  const profile = id === "nexacorp"
    ? NEXACORP_PROFILE
    : (COMPANY_PROFILES.find(c => c.id === id) ?? NEXACORP_PROFILE);
  const active: string[] = profile.architecture?.sources ?? [];
  return [
    { value: "all", label: "All Sources" },
    ...SOURCES.filter(s => s.value !== "all" && active.includes(s.value)),
  ];
}

export default function DashboardPage() {
  // ── All state up-front ────────────────────────────────────────────────────
  const [showTrainingModal,   setShowTrainingModal]   = useState(false);
  const [showWelcome,         setShowWelcome]         = useState(false);
  const [showCompanySelector, setShowCompanySelector] = useState(false);
  const [selectedCompanyId,   setSelectedCompanyId]   = useState("nexacorp");
  // Session attack story — picked client-side in the mount effect (localStorage
  // anti-repeat memory is unavailable during SSR). All stories injected this
  // session are tracked so the incident-report grader gets true ground truth.
  const [sessionStory,     setSessionStory]     = useState<AttackStory | null>(null);
  const [injectedStories,  setInjectedStories]  = useState<AttackStory[]>([]);
  const [scenarioObjective,   setScenarioObjective]   = useState<string | null>(null);
  // Session clock — set when a training session starts, cleared when it ends.
  // Drives the "session active" indicator so the analyst always knows whether
  // a graded session is running and how long they've been on shift.
  const [sessionStartedAt,    setSessionStartedAt]    = useState<number | null>(null);
  const [sessionDifficulty,   setSessionDifficulty]   = useState<Difficulty | null>(null);
  const [sessionElapsed,      setSessionElapsed]      = useState(0);
  const [showReportModal,     setShowReportModal]     = useState(false);
  const [showChainBoard,      setShowChainBoard]      = useState(false);

  // ─── Company progression ──────────────────────────────────────────────────
  const [unlockedCompanies, setUnlockedCompanies] = useState<string[]>(() => {
    if (typeof window === "undefined") return ["nexacorp"];
    try { return JSON.parse(localStorage.getItem(UNLOCKED_KEY) ?? '["nexacorp"]'); } catch { return ["nexacorp"]; }
  });
  const [clearedCompanies, setClearedCompanies] = useState<string[]>(() => {
    if (typeof window === "undefined") return [];
    try { return JSON.parse(localStorage.getItem(CLEARED_KEY) ?? "[]"); } catch { return []; }
  });
  const [showClearedModal, setShowClearedModal] = useState(false);

  // ─── Session summary modal ────────────────────────────────────────────────
  const [sessionSummary, setSessionSummary] = useState<DashboardSessionRecord | null>(null);

  // ─── Progress counters (session-scoped, reset on company switch) ─────────
  const [reportPassed,    setReportPassed]    = useState(false);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<"all" | "low" | "medium" | "high">("all");
  const [sourceFilter,   setSourceFilter]   = useState("all");
  const [userFilter,     setUserFilter]     = useState("all");
  const [hostFilter,     setHostFilter]     = useState("all");
  const [ipFilter,       setIpFilter]       = useState("all");
  const [mitreFilter,    setMitreFilter]    = useState("all");
  const [search,         setSearch]         = useState("");
  // Row 2 (User/Host/IP/MITRE) is hidden by default — beginners rarely need it
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const advancedFilterCount =
    (userFilter !== "all" ? 1 : 0) + (hostFilter !== "all" ? 1 : 0) +
    (ipFilter !== "all" ? 1 : 0) + (mitreFilter !== "all" ? 1 : 0);

  // ── live hook declared here so ALL handlers below can reference it ────────
  // Static pool mode: shuffle from benignEvents so the feed shows diverse sources
  // (EDR, O365, Firewall, Sysmon, etc.) not just AD.
  // liveRef lets onStoryComplete (called from inside the hook) reach live.startStory.
  const liveRef = useRef<import("./useLiveEvents").LiveEventsApi | null>(null);
  const handleStoryComplete = () => {
    const nextStory = instantiateStory(
      pickStoryForCompany(selectedCompanyId),
      getCompanyEvents(selectedCompanyId)
    );
    setSessionStory(nextStory);
    setInjectedStories(prev => [...prev, nextStory]);
    liveRef.current?.startStory(nextStory);
  };
  // Memoize the pool/profile lookups: getCompanyEvents filters ~8000 benign
  // events, and without memoization it ran on EVERY render and handed a fresh
  // array identity to useLiveEvents each pass — which re-triggered the hook's
  // effects and was the root cause of the "setState during render" warning.
  const eventPool       = useMemo(() => getCompanyEvents(selectedCompanyId), [selectedCompanyId]);
  const selectedCompany = useMemo(() => getCompanyProfile(selectedCompanyId), [selectedCompanyId]);

  const live = useLiveEvents({
    eventPool,
    intervalMs: 90_000,   // 90s between ticks — readable pace for training
    story:      sessionStory,
    onStoryComplete: handleStoryComplete,
  });
  liveRef.current = live;

  // ── Persist session XP to localStorage (cumulative across sessions) ───────
  const prevSessionXpRef = useRef(0);
  useEffect(() => {
    const delta = live.sessionXp - prevSessionXpRef.current;
    if (delta > 0 && typeof window !== "undefined") {
      addTotalXp(delta);
      localStorage.setItem("soc_last_session", new Date().toISOString());
    }
    prevSessionXpRef.current = live.sessionXp;
  }, [live.sessionXp]);

  // ── On mount: restore saved company, arm the session story, pick modal ────
  useEffect(() => {
    if (typeof window === "undefined") return;
    const saved    = localStorage.getItem(COMPANY_KEY);
    const seenWelcome = localStorage.getItem(WELCOME_KEY);

    // Pick this session's attack story for the active company (client-side only —
    // the anti-repeat memory lives in localStorage) and arm the scheduler.
    const companyId = saved ?? "nexacorp";
    const story = instantiateStory(pickStoryForCompany(companyId), getCompanyEvents(companyId));
    setSessionStory(story);
    setInjectedStories([story]);
    if (saved && saved !== "nexacorp") {
      setSelectedCompanyId(saved);
      live.reset(getCompanyEvents(saved), story);
    } else {
      live.reset(undefined, story);
    }

    if (!seenWelcome) {
      setShowWelcome(true);
    } else if (!saved) {
      setShowCompanySelector(true);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);   // intentionally runs once on mount only

  // ── Handlers ─────────────────────────────────────────────────────────────
  const handleCloseWelcome = () => {
    localStorage.setItem(WELCOME_KEY, "1");
    setShowWelcome(false);
    if (!localStorage.getItem(COMPANY_KEY)) setShowCompanySelector(true);
  };

  /** Briefing → guided tour. Dismiss the modal FIRST so the two never overlap. */
  const handleTakeTour = () => {
    localStorage.setItem(WELCOME_KEY, "1");
    setShowWelcome(false);
    startDashboardTour();
  };

  const handleSelectCompany = (id: string) => {
    setSelectedCompanyId(id);
    localStorage.setItem(COMPANY_KEY, id);
    setShowCompanySelector(false);
    setSourceFilter("all");
    setReportPassed(false);
    const newStory = instantiateStory(pickStoryForCompany(id), getCompanyEvents(id));
    setSessionStory(newStory);
    setInjectedStories([newStory]);
    live.reset(getCompanyEvents(id), newStory);
  };

  const hasActiveFilters =
    severityFilter !== "all" || sourceFilter !== "all" ||
    userFilter !== "all" || hostFilter !== "all" ||
    ipFilter !== "all" || mitreFilter !== "all" || search !== "";

  const clearAllFilters = () => {
    setSeverityFilter("all"); setSourceFilter("all");
    setUserFilter("all"); setHostFilter("all");
    setIpFilter("all"); setMitreFilter("all");
    setSearch("");
  };

  // ── Dynamic KPIs ─────────────────────────────────────────────────────────────
  const threatLevel = useMemo(() => {
    const recent = live.events.slice(0, 20);
    const highCount = recent.filter(e => e.ruleLevel >= 7).length;
    const medCount  = recent.filter(e => e.ruleLevel >= 4 && e.ruleLevel < 7).length;
    if (highCount / recent.length > 0.4) return "High";
    if ((highCount + medCount) / recent.length > 0.3) return "Medium";
    return "Low";
  }, [live.events]);

  // Dynamic filter options — populated from whatever is currently in the feed
  const filterOptions = useMemo(() => {
    const users  = Array.from(new Set(live.events.map(e => e.user_email).filter(Boolean))) as string[];
    const hosts  = Array.from(new Set(live.events.map(e => e.hostname).filter(Boolean)))  as string[];
    const ips    = Array.from(new Set(live.events.map(e => e.src_ip).filter(Boolean)))    as string[];
    const mitres = Array.from(new Set(live.events.map(e => e.mitre_technique).filter(Boolean))) as string[];
    return { users, hosts, ips, mitres };
  }, [live.events]);

  const threatLevelColor =
    threatLevel === "High"   ? "text-severity-critical" :
    threatLevel === "Medium" ? "text-severity-medium" :
                               "text-neon-green";

  // ── Company progression helpers ───────────────────────────────────────────
  const nextCompanyId = COMPANY_ORDER[COMPANY_ORDER.indexOf(selectedCompanyId) + 1] ?? null;
  const nextCompany   = nextCompanyId ? COMPANY_PROFILES.find(c => c.id === nextCompanyId) ?? null : null;

  const handleClearCompany = () => {
    const newCleared = [...new Set([...clearedCompanies, selectedCompanyId])];
    setClearedCompanies(newCleared);
    localStorage.setItem(CLEARED_KEY, JSON.stringify(newCleared));
    if (nextCompanyId) {
      const newUnlocked = [...new Set([...unlockedCompanies, nextCompanyId])];
      setUnlockedCompanies(newUnlocked);
      localStorage.setItem(UNLOCKED_KEY, JSON.stringify(newUnlocked));
    }
    setSessionSummary(null);
    setShowClearedModal(true);
  };

  const handleClearedContinue = () => {
    setShowClearedModal(false);
    if (nextCompanyId) handleSelectCompany(nextCompanyId);
  };

  // ── Start training ─────────────────────────────────────────────────────────────
  const handleStartTraining = (difficulty: Difficulty) => {
    // Fresh session for the current company at the chosen difficulty. A new
    // attack story is picked at RANDOM within the difficulty's complexity
    // tier and kept hidden — the objective text never reveals the attack
    // type, so the analyst must find it themselves. Easy is restricted to
    // single-host "foundation" stories (see attackStories.ts) so a student's
    // first attacks are never a full lateral-movement/credential-theft chain.
    const story = instantiateStory(pickStoryForCompany(selectedCompanyId, difficulty), getCompanyEvents(selectedCompanyId));
    setSessionStory(story);
    setInjectedStories([story]);
    const label = difficulty[0].toUpperCase() + difficulty.slice(1);
    setScenarioObjective(`${label} session — watch the feed, identify the attack hidden in it, and report it. You will not be told what it is.`);
    setSessionStartedAt(Date.now());
    setSessionDifficulty(difficulty);
    setSessionElapsed(0);
    live.reset(getCompanyEvents(selectedCompanyId), story);
  };

  /** Ends the session and stops the clock. */
  const handleEndSession = () => {
    setSessionSummary(live.endSession());
    setSessionStartedAt(null);
    setSessionDifficulty(null);
  };

  // Tick the session clock once a second while a session is running.
  useEffect(() => {
    if (sessionStartedAt === null) return;
    const id = setInterval(() => {
      setSessionElapsed(Math.floor((Date.now() - sessionStartedAt) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, [sessionStartedAt]);

  const sessionClock = `${String(Math.floor(sessionElapsed / 60)).padStart(2, "0")}:${String(sessionElapsed % 60).padStart(2, "0")}`;

  const handleXpAward = (_delta: number) => {
    // Stub — AttackChainBoard requires an onXpAward prop but doesn't currently
    // award XP itself; it's a read-only reconstruction view after a catch.
  };

  return (
    <div>
      {showWelcome && <SOCWelcomeModal onStart={handleCloseWelcome} onTakeTour={handleTakeTour} />}

      {showCompanySelector && (
        <CompanySelector
          currentId={selectedCompanyId}
          onSelect={handleSelectCompany}
          onClose={localStorage.getItem(COMPANY_KEY) ? () => setShowCompanySelector(false) : undefined}
          unlockedIds={unlockedCompanies}
          clearedIds={clearedCompanies}
        />
      )}

      {showTrainingModal && (
        <StartTrainingModal
          onStart={handleStartTraining}
          onClose={() => setShowTrainingModal(false)}
        />
      )}

      <Topbar
        title={`SOC Dashboard — ${selectedCompany.name}`}
        subtitle={`${selectedCompany.industry} · ${selectedCompany.hq} · ${selectedCompany.size.toLocaleString()} employees`}
        actions={
          <div className="flex items-center gap-2">
            {/* The SIEM tour is opt-in (it no longer auto-opens over the shift
                briefing), so it needs a permanent, discoverable way back in. */}
            <button
              onClick={startDashboardTour}
              title="Replay the SIEM dashboard tour"
              className="flex items-center gap-1.5 rounded border border-border bg-bg px-2.5 py-1.5 text-xs text-slate-300 hover:bg-bg-hover transition"
            >
              <BookOpen className="h-3.5 w-3.5 text-slate-400" />
              Tour
            </button>
            <button
              onClick={() => setShowCompanySelector(true)}
              className="flex items-center gap-1.5 rounded border border-border bg-bg px-2.5 py-1.5 text-xs text-slate-300 hover:bg-bg-hover transition"
            >
              <Building2 className="h-3.5 w-3.5 text-slate-400" />
              Switch Company
            </button>
            {/* Report Incident — the key action, and the only place the analyst
                is graded. Solid CTA throughout; no pulse/hint tied to whether
                they've "caught" anything — that would leak the answer. */}
            <button
              id="report-incident-btn"
              onClick={() => setShowReportModal(true)}
              className={cn(
                "flex items-center gap-1.5 rounded-md px-3.5 py-2 text-xs font-bold shadow transition",
                reportPassed
                  ? "bg-neon-green text-bg hover:bg-neon-green/90"
                  : "bg-neon-purple text-white hover:brightness-110",
              )}
            >
              <FileText className="h-4 w-4" />
              {reportPassed ? "Report Submitted ✓" : "Report Incident"}
            </button>
            <button
              onClick={handleEndSession}
              className="flex items-center gap-1.5 rounded border border-neon-amber/40 bg-neon-amber/8 px-2.5 py-1.5 text-xs font-semibold text-neon-amber hover:bg-neon-amber/15 transition"
            >
              <LogOut className="h-3.5 w-3.5" />
              End Session
            </button>
            <Button variant="primary" size="sm" onClick={() => setShowTrainingModal(true)}>
              <Target className="h-4 w-4" /> Start Training
            </Button>
          </div>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">

        {/* Session status bar — one compact row instead of the old KPI grid + XP banner */}
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 rounded-lg border border-border bg-bg-elevated px-5 py-3">
          <span className="flex items-center gap-2 text-xs text-slate-400">
            <Star className="h-4 w-4 text-cyber-300" />
            <span className="font-semibold text-white">Session XP</span>
            <span className="font-mono text-sm font-bold text-cyber-300">{live.sessionXp}</span>
          </span>
          <span className="flex items-center gap-2 text-xs text-slate-400">
            <span className="font-semibold text-white">Threat Level</span>
            <span className={cn("font-mono text-sm font-bold", threatLevelColor)}>{threatLevel}</span>
          </span>
          <span className="flex items-center gap-2 text-xs text-slate-400">
            <BookOpen className="h-3.5 w-3.5 text-slate-500" />
            <span className="font-semibold text-white">Companies</span>
            <span className="font-mono text-sm font-bold text-neon-purple">{clearedCompanies.length}/{COMPANY_ORDER.length}</span>
          </span>
          {/* Session state — the analyst should never have to guess whether a
              graded session is running. Live pulse + elapsed clock when active,
              an explicit idle hint when not. */}
          {sessionStartedAt !== null ? (
            <span className="ml-auto flex items-center gap-2.5 rounded-full border border-neon-green/40 bg-neon-green/10 px-3.5 py-1.5">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-70" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" />
              </span>
              <span className="text-[11px] font-bold uppercase tracking-wider text-neon-green">Session active</span>
              {sessionDifficulty && (
                <span className="rounded border border-neon-green/30 px-1.5 py-px text-[10px] font-semibold uppercase text-neon-green/80">
                  {sessionDifficulty}
                </span>
              )}
              <span className="font-mono text-xs font-bold text-white">{sessionClock}</span>
            </span>
          ) : (
            <span className="ml-auto flex items-center gap-2 text-xs text-slate-500">
              <span className="h-2 w-2 rounded-full bg-slate-600" />
              No active session — press
              <span className="font-semibold text-slate-400">Start Training</span>
            </span>
          )}
        </div>

        {/* Scenario objective banner */}
        {scenarioObjective && (
          <div className="flex items-center gap-3 rounded-lg border border-neon-purple/30 bg-neon-purple/5 px-5 py-3">
            <Target className="h-4 w-4 shrink-0 text-neon-purple" />
            <p className="text-sm text-slate-200">{scenarioObjective}</p>
            <button onClick={() => setScenarioObjective(null)} className="ml-auto text-slate-500 hover:text-slate-300">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Missed-attack debrief — a coaching moment, never a silent penalty */}
        {live.missedAttack && (() => {
          const ids = new Set(live.activeIncident?.eventIds ?? []);
          const missedEvents = live.events.filter(e => ids.has(e.id)).slice(0, 6);
          return (
            <div className="rounded-lg border border-neon-amber/40 bg-neon-amber/5 px-5 py-4">
              <div className="flex items-start gap-3">
                <Siren className="mt-0.5 h-5 w-5 shrink-0 text-neon-amber" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-bold text-white">An attack slipped past — let&apos;s debrief</p>
                  <p className="mt-0.5 text-xs text-slate-300 leading-relaxed">
                    <span className="font-semibold text-neon-amber">{live.activeIncident?.title ?? "A multi-stage attack"}</span>{" "}
                    ran its course before it was reported. No points lost — spotting the ones you miss is exactly how you build the eye for it. Here&apos;s what it looked like:
                  </p>
                  {missedEvents.length > 0 && (
                    <ul className="mt-2 space-y-1">
                      {missedEvents.map(e => (
                        <li key={e.id} className="flex gap-2 text-[11px] text-slate-400">
                          <span className="shrink-0 font-mono text-slate-600">{new Date(e.ts).toLocaleTimeString("en-GB")}</span>
                          <span className="truncate">{e.description ?? e.displayDescription}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="mt-2 text-[11px] text-slate-500">
                    Next time: when a process looks off, widen the timeline around it and check what it spawned and what it connected out to.
                  </p>
                </div>
                <button
                  onClick={() => { live.clearMissedAttack(); live.dismissIncident(); }}
                  className="shrink-0 text-slate-500 hover:text-slate-300"
                  aria-label="Dismiss debrief"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
          );
        })()}

        {/* Analyst workflow — persistent "what do I do now?" strip */}
        <WorkflowGuide reportPassed={reportPassed} />

        {/* Live Event Feed */}
        <div className="flex gap-4 items-start">
          <div className="min-w-0 flex-1">
          <Card padded={false} className="overflow-hidden">
          {/* Feed header */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3">
            <div className="flex items-center gap-3">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-neon-green" />
              </span>
              <div>
                <h3 className="text-sm font-semibold text-white">Live Event Feed</h3>
                <p className="text-[10px] text-slate-500">Click a row to expand and read the full log</p>
              </div>
            </div>

            {/* Controls */}
            <div className="flex items-center gap-2">
              {/* Search */}
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
                <input
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search events…"
                  className="h-8 w-52 rounded border border-border bg-bg pl-8 pr-3 text-xs text-slate-200 placeholder-slate-500 focus:border-cyber-500/50 focus:outline-none"
                />
              </div>

              {/* Pause / resume */}
              <button
                onClick={live.isStreaming ? live.pause : live.resume}
                className="flex items-center gap-1.5 rounded border border-border bg-bg px-2.5 py-1.5 text-xs text-slate-300 hover:bg-bg-hover"
              >
                {live.isStreaming
                  ? <><Pause className="h-3.5 w-3.5" /> Pause</>
                  : <><Play  className="h-3.5 w-3.5 text-neon-green" /> Resume</>}
              </button>

              {/* Reset */}
              <button
                onClick={() => live.reset()}
                className="flex items-center gap-1.5 rounded border border-border bg-bg px-2.5 py-1.5 text-xs text-slate-300 hover:bg-bg-hover"
                title="Clear and restart"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Filter bar — row 1: level + source */}
          <div className="flex flex-wrap items-center gap-3 border-b border-border/60 bg-bg/60 px-5 py-2.5">
            <Filter className="h-3.5 w-3.5 shrink-0 text-slate-500" />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-500">Level:</span>

            <div className="flex gap-1">
              {(["all", "low", "medium", "high"] as const).map((lv) => (
                <button
                  key={lv}
                  onClick={() => setSeverityFilter(lv)}
                  className={cn(
                    "rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider transition",
                    severityFilter === lv
                      ? lv === "high"   ? "border-severity-critical/60 bg-severity-critical/15 text-severity-critical" :
                        lv === "medium" ? "border-severity-medium/60 bg-severity-medium/15 text-severity-medium" :
                        lv === "low"    ? "border-slate-500/60 bg-slate-500/15 text-slate-300" :
                                          "border-cyber-500/60 bg-cyber-500/15 text-cyber-300"
                      : "border-border text-slate-500 hover:border-border-strong hover:text-slate-300"
                  )}
                >
                  {lv === "all" ? "All" : lv === "low" ? "1-3 Low" : lv === "medium" ? "4-6 Med" : "7-10 High"}
                </button>
              ))}
            </div>

            <span className="text-[10px] text-slate-600">|</span>

            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="h-6 rounded border border-border bg-bg px-2 text-[10px] text-slate-300 focus:border-cyber-500/50 focus:outline-none"
            >
              {getSourcesForCompany(selectedCompanyId).map(s => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>

            <button
              onClick={() => setShowAdvancedFilters(v => !v)}
              className={cn(
                "ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold transition",
                advancedFilterCount > 0
                  ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300"
                  : "border-border text-slate-500 hover:text-slate-300 hover:border-border-strong"
              )}
            >
              {showAdvancedFilters ? "− Fewer filters" : `+ More filters${advancedFilterCount > 0 ? ` (${advancedFilterCount})` : ""}`}
            </button>
            {hasActiveFilters && (
              <button
                onClick={clearAllFilters}
                className="flex items-center gap-1 rounded border border-severity-high/40 bg-severity-high/10 px-2 py-0.5 text-[10px] font-semibold text-severity-high hover:bg-severity-high/20 transition"
              >
                <X className="h-3 w-3" /> Clear filters
              </button>
            )}
          </div>

          {/* Filter bar — row 2: user / host / IP / MITRE (progressive disclosure) */}
          {showAdvancedFilters && (
          <div className="flex flex-wrap items-center gap-2 border-b border-border/60 bg-[#080d14] px-5 py-2.5">

            {/* User — blue */}
            <div className={cn(
              "flex items-center gap-1.5 rounded-md border px-2.5 py-1 transition",
              userFilter !== "all"
                ? "border-neon-blue/60 bg-neon-blue/10"
                : "border-border/60 bg-bg hover:border-border-strong"
            )}>
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">User</span>
              <select
                value={userFilter}
                onChange={(e) => setUserFilter(e.target.value)}
                className={cn(
                  "bg-transparent text-[11px] font-mono font-semibold focus:outline-none cursor-pointer",
                  userFilter !== "all" ? "text-neon-blue" : "text-slate-300"
                )}
              >
                <option value="all">All</option>
                {filterOptions.users.sort().map(u => (
                  <option key={u} value={u}>{u}</option>
                ))}
              </select>
            </div>

            {/* Host — green */}
            <div className={cn(
              "flex items-center gap-1.5 rounded-md border px-2.5 py-1 transition",
              hostFilter !== "all"
                ? "border-neon-green/60 bg-neon-green/10"
                : "border-border/60 bg-bg hover:border-border-strong"
            )}>
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">Host</span>
              <select
                value={hostFilter}
                onChange={(e) => setHostFilter(e.target.value)}
                className={cn(
                  "bg-transparent text-[11px] font-mono font-semibold focus:outline-none cursor-pointer",
                  hostFilter !== "all" ? "text-neon-green" : "text-slate-300"
                )}
              >
                <option value="all">All</option>
                {filterOptions.hosts.sort().map(h => (
                  <option key={h} value={h}>{h}</option>
                ))}
              </select>
            </div>

            {/* IP — amber */}
            <div className={cn(
              "flex items-center gap-1.5 rounded-md border px-2.5 py-1 transition",
              ipFilter !== "all"
                ? "border-neon-amber/60 bg-neon-amber/10"
                : "border-border/60 bg-bg hover:border-border-strong"
            )}>
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">IP</span>
              <select
                value={ipFilter}
                onChange={(e) => setIpFilter(e.target.value)}
                className={cn(
                  "bg-transparent text-[11px] font-mono font-semibold focus:outline-none cursor-pointer",
                  ipFilter !== "all" ? "text-neon-amber" : "text-slate-300"
                )}
              >
                <option value="all">All</option>
                {filterOptions.ips.sort().map(ip => (
                  <option key={ip} value={ip}>{ip}</option>
                ))}
              </select>
            </div>

            {/* MITRE — purple */}
            <div className={cn(
              "flex items-center gap-1.5 rounded-md border px-2.5 py-1 transition",
              mitreFilter !== "all"
                ? "border-neon-purple/60 bg-neon-purple/10"
                : "border-border/60 bg-bg hover:border-border-strong"
            )}>
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">MITRE</span>
              <select
                value={mitreFilter}
                onChange={(e) => setMitreFilter(e.target.value)}
                className={cn(
                  "bg-transparent text-[11px] font-mono font-semibold focus:outline-none cursor-pointer",
                  mitreFilter !== "all" ? "text-neon-purple" : "text-slate-300"
                )}
              >
                <option value="all">All</option>
                {filterOptions.mitres.sort().map(t => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>

            <span className="ml-auto text-[10px] text-slate-600 font-mono">
              {filterOptions.users.length}u · {filterOptions.hosts.length}h · {filterOptions.ips.length} IPs
            </span>
          </div>
          )}


          <SiemStats
            events={live.events}
            attackTimerSeconds={live.attackTimerSeconds}
            avgCatchMs={live.avgCatchMs}
          />

          {/* The actual feed — pure investigation surface. No alert queue, no
              per-row grading — the analyst reads the logs, forms their own
              conclusion, and states it once in the Incident Report, where it's
              actually graded. */}
          <EventFeed
            events={live.events}
            newIds={live.newIds}
            severityFilter={severityFilter}
            sourceFilter={sourceFilter}
            userFilter={userFilter}
            hostFilter={hostFilter}
            ipFilter={ipFilter}
            mitreFilter={mitreFilter}
            search={search}
            onXp={live.addXp}
            onRowOpened={live.recordEventOpened}
          />
        </Card>
          </div>
        </div>

      </div>


      {/* ── Incident Report Modal ───────────────────────────────────── */}
      {showReportModal && (() => {
        // Ground truth = what was actually injected this session (all stories),
        // not what the student happened to classify.
        const storyMitre = Array.from(new Set(injectedStories.flatMap(s => s.mitre)));
        const storyTitle = injectedStories.map(s => s.title).join(" + ") || null;
        // Ground-truth indicators pulled from the ACTUAL injected attack events —
        // the grader uses these to verify the student cited real evidence and to
        // catch fabricated data (e.g. a hostname that never appears in the logs).
        const realIndicators = extractIndicators(injectedStories.flatMap(s => s.events));
        return (
          <IncidentReportModal
            companyName={selectedCompany.name}
            companyId={selectedCompanyId}
            realIndicators={realIndicators}
            attackTitle={storyTitle}
            attackMitreTechniques={storyMitre}
            onClose={() => setShowReportModal(false)}
            onPassed={() => {
              setReportPassed(true);
              // A passing report IS the catch — register it for real. Without
              // this, markCaught() was never called from anywhere: the SLA
              // never cleared on a correct report, avgCatchMs/attacksCaughtCount
              // stayed permanently empty, and the miss-timer would still fire
              // later and count a genuinely-caught attack as missed.
              const caughtIds = live.activeIncident?.eventIds ?? [];
              if (caughtIds.length > 0) live.markCaught(caughtIds[0]);
            }}
          />
        );
      })()}

      {/* ── Attack Chain Board (LO-3 / Upgrade 5) ───────────────────── */}
      {(showChainBoard || live.lastAttackChain) && live.lastAttackChain && (
        <AttackChainBoard
          events={live.lastAttackChain}
          onClose={() => { setShowChainBoard(false); live.clearLastAttackChain(); }}
          onXpAward={handleXpAward}
        />
      )}

      {/* ── Session Summary Modal ──────────────────────────────────────── */}
      {sessionSummary && (() => {
        const objDefs = COMPANY_OBJECTIVES[selectedCompanyId] ?? [];
        const objWithMet = objDefs.map(o => ({ label: o.label, met: o.met(sessionSummary, reportPassed) }));
        const allMet = objWithMet.length > 0 && objWithMet.every(o => o.met);
        return (
          <SessionSummaryModal
            record={sessionSummary}
            reportPassed={reportPassed}
            onClose={() => setSessionSummary(null)}
            objectives={objWithMet}
            canClearCompany={allMet && !clearedCompanies.includes(selectedCompanyId)}
            nextCompanyName={nextCompany?.name}
            onClearCompany={handleClearCompany}
          />
        );
      })()}

      {/* ── Company Cleared Modal ──────────────────────────────────────── */}
      {showClearedModal && (
        <CompanyClearedModal
          clearedCompanyName={selectedCompany.name}
          nextCompanyName={nextCompany?.name ?? null}
          onContinue={handleClearedContinue}
        />
      )}

    </div>
  );
}
