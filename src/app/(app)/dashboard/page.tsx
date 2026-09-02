"use client";
import { useEffect, useMemo, useRef, useState } from "react";
import type { AttackStory } from "./attackStories";
import { Topbar } from "@/components/nav/Topbar";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/utils";
import { loadSimData, type SimData, type Difficulty } from "./simData";
import { useLiveEvents } from "./useLiveEvents";
import { EventFeed } from "./EventFeed";
import { getClearedCompanies, addClearedCompany, setLastSession, getRoomProgress } from "@/lib/storage/progress";
import Link from "next/link";
import { WorkflowGuide } from "./WorkflowGuide";
import { HintPanel } from "./HintPanel";
import { SavedSearches, type FilterSnapshot } from "./SavedSearches";
import { SiemStats } from "./SiemStats";
import { CompanySelector } from "./CompanySelector";
import { IncidentReportModal } from "./IncidentReportModal";
import { AttackChainBoard } from "./AttackChainBoard";
import { CompanyClearedModal } from "./CompanyClearedModal";
import { startDashboardTour } from "./OnboardingTour";
import { COMPANY_PROFILES, NEXACORP_PROFILE } from "@/lib/sim/companyProfilesMeta";
import type { CompanyProfile } from "@/lib/sim/companyProfilesMeta";
import type { TelemetryEvent } from "@/lib/sim/types";
import { fetchOrgCompanies, type OrgCompanyContent } from "@/lib/content/publicContent";
import { containedHosts, EDR_CONTAINMENT_EVENT } from "@/lib/edr/containment";
import { setTrainingActive } from "@/lib/sim/trainingSession";
import { isSha256Field, isIpCheckField, isDomainCheckField } from "@/components/threat-intel/ThreatIntelDrawer";
import {
  BookOpen, Building2, Clock, Cpu, FileText, Filter, GraduationCap, Pause, Play,
  RefreshCw, Search, ShieldCheck, Siren, Star, Target, X, Zap,
} from "lucide-react";

const COMPANY_KEY       = "soc_selected_company_v1";  // device-local UI preference (which company is open)
const COMPANY_ORDER     = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"];

// Auto-advance rule: catch this many attacks within this rolling window and the
// company is secured AUTOMATICALLY and the next one unlocks — this replaces the
// manual "End Session → Secure This Company" gate.
const ADVANCE_CATCHES   = 2;
const ADVANCE_WINDOW_MS = 30 * 60_000; // 30 minutes
const MISSION_BONUS_XP  = 250;         // session-XP reward for completing the mission


// The analyst's ONE deliverable per company: a passing incident report. It
// already grades attack identification + evidence + action + impact holistically
// (see /api/dashboard/incident-report), so there's no separate "classify N
// events" gate — that would just be a second, redundant scoring mechanism.
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
    const procObj = e.process as { name?: string; hash?: { sha256?: string } } | undefined;
    if (procObj?.name) out.add(procObj.name);
    if (procObj?.hash?.sha256) out.add(procObj.hash.sha256);
    // Also harvest indicators that live ONLY in the vendor-native `raw` block —
    // the exact same fields the Threat-Intel drawer lets the analyst "Check
    // Hash / Check IP / Check Domain" on. A SHA-256 the student pulled from
    // cs.SHA256HashData (or Sysmon Hashes, Defender SHA256, …) is a real,
    // observable artifact; if it isn't harvested here the report grader has no
    // record of it and wrongly brands the student's citation "fabricated". Use
    // the SAME recognisers the drawer uses so ground truth == what's checkable.
    const raw = (e.raw ?? {}) as Record<string, unknown>;
    for (const [k, v] of Object.entries(raw)) {
      if (typeof v !== "string" || !v.trim()) continue;
      const val = v.trim();
      if (isSha256Field(k, val) || isIpCheckField(k, val) || isDomainCheckField(k, val)) {
        out.add(val);
      }
    }
  }
  return Array.from(out);
}

// ─── Source filter options ─────────────────────────────────────────────────────

const SOURCES = [
  { value: "all",        label: "All Sources" },
  { value: "edr",        label: "EDR" },
  { value: "ad",         label: "Active Directory" },
  { value: "windows_security", label: "Windows Security" },
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
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Severity</span>
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

// Difficulty is defined in ./simData (a leaf module) to avoid an import cycle;
// re-exported here so existing `import { Difficulty } from ".../dashboard/page"`
// consumers keep working.
export type { Difficulty };

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

// Helper: get event pool for a given company id — DNS always excluded from live
// feed. Takes the lazily-loaded sim data (benign + per-company pools) — see
// simData.ts; the dashboard has it in hand before any pool is ever needed
// (loaded at "Start Training").
function getCompanyEvents(sim: SimData, id: string) {
  const base = id === "nexacorp" ? sim.BENIGN_EVENTS : (sim.COMPANY_EVENTS[id] ?? sim.BENIGN_EVENTS);
  // L-03 / L-09: emit ONLY the sources this company's architecture actually runs.
  // The pool used to leak 12+ sources — a second competing EDR, AWS WAF/RDS on an
  // Azure estate, DLP/Linux/email that the company never declared — regardless of
  // the stack, which contradicts the Security-Products and Asset-Context rooms and
  // left the source filter menu (correctly limited to the declared sources) unable
  // to select half of what was on screen. Aligning the feed to architecture.sources
  // makes "Switch Company" a real change of telemetry and makes the filter complete.
  const active = new Set(getCompanyProfile(id).architecture?.sources ?? []);
  return base.filter(e => e.source !== "dns" && (active.size === 0 || active.has(e.source)));
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
  // Readiness signal (PM audit F6): the dashboard is self-paced and stays open,
  // but a learner who has cleared 0 rooms is about to read real production logs
  // with no scaffolding. We show a soft, dismissible "start with the basics"
  // banner — not a lock (the freedom to explore early is intentional). `ready`
  // defaults to true so the banner never flashes before we've read progress.
  const [roomReady,           setRoomReady]           = useState(true);
  const [readinessDismissed,  setReadinessDismissed]  = useState(true);
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
  // Writing the incident report auto-pauses the live feed (a real analyst stops
  // watching to write up the ticket). pausedForReport marks that WE paused it,
  // so on close we offer to resume; showResumePrompt is that "continue?" dialog.
  const [pausedForReport,     setPausedForReport]     = useState(false);
  const [showResumePrompt,    setShowResumePrompt]    = useState(false);

  // ─── Company progression ──────────────────────────────────────────────────
  // Cleared companies persist through the storage facade → DB (user_progress.
  // cleared_companies) for signed-in users, localStorage for guests. Previously
  // this read/wrote raw localStorage, which for a signed-in user NEVER reached
  // the DB (silent progress loss across devices) — QA finding, same class as the
  // scenario/room/dashboard persistence migration.
  const [clearedCompanies, setClearedCompanies] = useState<string[]>(() => getClearedCompanies());
  // Unlocked is DERIVED, not separately stored: a company is open iff it is the
  // first one or its predecessor in COMPANY_ORDER has been cleared. (The old
  // UNLOCKED_KEY was never in the facade/DB at all.)
  const unlockedCompanies = useMemo(
    () => COMPANY_ORDER.filter((_, i) => i === 0 || clearedCompanies.includes(COMPANY_ORDER[i - 1])),
    [clearedCompanies],
  );
  const [showClearedModal, setShowClearedModal] = useState(false);

  // ─── Session summary modal ────────────────────────────────────────────────

  // ─── Hosts contained in the EDR console ───────────────────────────────────
  // Shared state with /edr: isolating a host there marks it "Contained" here,
  // so the two surfaces read as one product (SIEM + EDR). Reactive to the EDR's
  // own event and to cross-tab storage writes.
  const [edrContained, setEdrContained] = useState<string[]>([]);
  useEffect(() => {
    const sync = () => setEdrContained(containedHosts());
    sync();
    window.addEventListener(EDR_CONTAINMENT_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(EDR_CONTAINMENT_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  // Did the student investigate in the EDR this shift? If so, nudge them to
  // actually file the incident report (set on the /edr decision; cleared on a
  // fresh shift and once the report passes). Reactive so returning from /edr
  // shows the reminder immediately.
  const [edrInvestigated, setEdrInvestigated] = useState(false);
  // True while the analyst is investigating the live case in the EDR console —
  // set when they open it, cleared when they finish there (the EDR decision
  // flips soc_edr_investigated), on a new incident, or by a safety cap so an
  // abandoned EDR tab can't freeze the response clock forever. Reactive (state,
  // not a ref) so both the SLA pause AND the "paused" badge update live.
  const [investigatingInEdr, setInvestigatingInEdr] = useState(false);
  const edrPauseCapRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    // The EDR runs in a separate tab, so the "student investigated" signal
    // arrives via the localStorage `storage` event (fires in OTHER tabs). Also
    // re-check on focus, for when they alt-tab back to the Dashboard.
    const sync = () => {
      try {
        const done = localStorage.getItem("soc_edr_investigated") === "1";
        setEdrInvestigated(done);
        // Finished in EDR → resume the clock; they now write the report (which
        // pauses it again). Keeps a walked-away EDR tab from freezing it.
        if (done) { setInvestigatingInEdr(false); if (edrPauseCapRef.current) { clearTimeout(edrPauseCapRef.current); edrPauseCapRef.current = null; } }
      } catch { /* ignore */ }
    };
    sync();
    window.addEventListener("storage", sync);
    window.addEventListener("soc:edr-investigated", sync);
    window.addEventListener("focus", sync);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("soc:edr-investigated", sync);
      window.removeEventListener("focus", sync);
    };
  }, []);

  // ─── Progress counters (session-scoped, reset on company switch) ─────────
  const [reportPassed,    setReportPassed]    = useState(false);
  // Timestamps of attacks caught this run — drives the "2 attacks in 30 minutes →
  // auto-advance" rule. caughtInWindow mirrors the count within the window for UI.
  const caughtTimesRef = useRef<number[]>([]);
  // Incidents already counted toward the auto-advance rule — dedup so a
  // re-submitted passing report can't double-count, double-award XP, or re-arm.
  const countedIncidentIdsRef = useRef<Set<string>>(new Set());
  const [caughtInWindow, setCaughtInWindow] = useState(0);
  // Time left (ms) to catch the next attack before the oldest catch rolls out of
  // the 30-min window — null when there are no catches in the window yet.
  const [windowRemainingMs, setWindowRemainingMs] = useState<number | null>(null);

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
  // Have we already armed the NEXT attack for the current incident? Reset when a
  // new incident opens (see the effect below). This enforces ONE incident at a
  // time: the next attack is armed only when the student files a passing report
  // (handleReportPassed), never automatically when a story finishes injecting.
  const armedNextRef = useRef(false);
  // Story completion no longer auto-arms the next attack — that let a second
  // incident pile on while the student was still working the first. An uncaught
  // story simply ends (no popup, no halt — the feed keeps streaming); a caught
  // one arms its successor from the report handler instead.
  const handleStoryComplete = () => { /* intentionally does nothing — see handleReportPassed */ };
  // Memoize the pool/profile lookups: getCompanyEvents filters ~8000 benign
  // events, and without memoization it ran on EVERY render and handed a fresh
  // array identity to useLiveEvents each pass — which re-triggered the hook's
  // effects and was the root cause of the "setState during render" warning.
  // Per-org authored live-feed environments (migration 0044). RLS returns only
  // this org's published companies; they merge into the selector, benign pool,
  // source filter and story picker below via the org-aware resolvers.
  const [orgCompanies, setOrgCompanies] = useState<OrgCompanyContent[]>([]);
  // Keep the in-flight fetch so "Start Training" can await org content before
  // resolving the pool — a returning org-user who clicks fast (before this
  // resolves) would otherwise silently get the generic built-in pool instead of
  // their org's authored environment.
  const orgLoadRef = useRef<Promise<OrgCompanyContent[]> | null>(null);
  useEffect(() => {
    const p = fetchOrgCompanies();
    orgLoadRef.current = p;
    p.then(setOrgCompanies).catch(() => {});
  }, []);
  const orgCompanyMap = useMemo(() => new Map(orgCompanies.map(c => [c.profile.id, c])), [orgCompanies]);
  const orgCompanyProfiles = useMemo(
    () => orgCompanies.map(c => ({ ...(c.profile as unknown as CompanyProfile), events: c.benignEvents as TelemetryEvent[] })),
    [orgCompanies],
  );

  // Org-aware lookups: an authored company id resolves from the DB content,
  // everything else falls through to the static built-ins unchanged.
  // The heavy simulation data (benign + attack event pools, story registry) is
  // loaded lazily — it's not in the dashboard's first-load bundle. `sim` is null
  // until the analyst starts a shift (or signals intent to); every event/story
  // resolver takes it explicitly so the type system enforces "loaded before use".
  const [sim, setSim] = useState<SimData | null>(null);
  // True when the lazy sim-data chunk failed to load (offline / chunk-hash swap
  // after a redeploy). Drives a visible retry banner instead of a silent
  // dead-end — see loadSimData() in simData.ts, which resets so a retry works.
  const [simLoadFailed, setSimLoadFailed] = useState(false);
  const ensureSim = async (): Promise<SimData> => {
    if (sim) return sim;
    try {
      const s = await loadSimData();
      setSim(s);
      setSimLoadFailed(false);
      return s;
    } catch (e) {
      setSimLoadFailed(true);
      throw e;
    }
  };

  const resolveEvents = (s: SimData, orgMap: Map<string, OrgCompanyContent>, id: string): TelemetryEvent[] => {
    const o = orgMap.get(id);
    if (o) return (o.benignEvents as TelemetryEvent[]).filter(e => e.source !== "dns");
    return getCompanyEvents(s, id);
  };
  // Profiles are light (companyProfilesMeta) and stay in the initial bundle — no
  // sim needed, so the Topbar/selector/source-filter render immediately.
  const resolveProfile = (id: string): CompanyProfile => {
    const o = orgCompanyMap.get(id);
    if (o) return { ...(o.profile as unknown as CompanyProfile), events: o.benignEvents as TelemetryEvent[] };
    return getCompanyProfile(id) as CompanyProfile;
  };
  const resolveSources = (id: string): { value: string; label: string }[] => {
    const o = orgCompanyMap.get(id);
    if (!o) return getSourcesForCompany(id);
    const active = o.profile.architecture?.sources ?? [];
    return [{ value: "all", label: "All Sources" }, ...SOURCES.filter(s => s.value !== "all" && active.includes(s.value))];
  };
  const resolveStory = (s: SimData, orgMap: Map<string, OrgCompanyContent>, id: string, difficulty?: Difficulty): AttackStory => {
    const o = orgMap.get(id);
    // L-03: pass the company's declared EDR so the attack arrives on the product it
    // actually runs (SentinelOne for MedCore, Sophos for GlobalLogis, …) instead of
    // always CrowdStrike.
    if (o) return s.instantiateStory(o.story as unknown as AttackStory, resolveEvents(s, orgMap, id), (o.profile.architecture as { edr?: string } | undefined)?.edr, id);
    return s.instantiateStory(s.pickStoryForCompany(id, difficulty), getCompanyEvents(s, id), getCompanyProfile(id).architecture?.edr, id);
  };

  // Empty until sim loads; the real pool is handed to the feed via live.reset()
  // at Start Training, so the feed (idle until then) never needs this early.
  const eventPool       = useMemo(() => (sim ? resolveEvents(sim, orgCompanyMap, selectedCompanyId) : []), [sim, selectedCompanyId, orgCompanyMap]); // eslint-disable-line react-hooks/exhaustive-deps
  const selectedCompany = useMemo(() => resolveProfile(selectedCompanyId), [selectedCompanyId, orgCompanyMap]); // eslint-disable-line react-hooks/exhaustive-deps

  // Endpoint view of THE attack currently in the feed — built from the live
  // story's real process telemetry. Null for pure identity/cloud attacks (no
  // process tree), in which case "Investigate in EDR" opens the static console.
  const liveEdrInvestigation = useMemo(
    () => (sim && sessionStory ? sim.buildInvestigationFromStory(sessionStory) : null),
    [sim, sessionStory],
  );

  const live = useLiveEvents({
    eventPool,
    intervalMs: 90_000,   // 90s between ticks — readable pace for training
    story:      sessionStory,
    onStoryComplete: handleStoryComplete,
    // Pause the response clock while the analyst is genuinely working the case:
    // the report modal is open, OR the EDR console is in play. That time is not
    // held against them (there is no fail — only the coaching metric).
    isInvestigating: () => showReportModal || investigatingInEdr,
    autoStart:  false,    // nothing streams until the student presses Start Training
  });
  liveRef.current = live;

  // Number of EDR alerts for the attack currently live in the feed. Non-zero
  // only while a shift is running AND an endpoint attack is active — an
  // identity/cloud attack produces no endpoint telemetry, so no EDR alerts.
  // Drives the badge that pops next to the "Investigate in EDR" button.
  const edrAlertCount = (live.activeIncident && liveEdrInvestigation)
    ? liveEdrInvestigation.detections.length : 0;

  // When a FRESH incident opens, reset the per-incident state so the student
  // works it cleanly: report button ready again, EDR reminder cleared, and the
  // next-attack arming re-enabled. This is what makes each incident a discrete
  // "handle it, report it, next" unit instead of a running pile.
  const prevIncidentIdRef = useRef<string | null>(null);
  useEffect(() => {
    const id = live.activeIncident?.id ?? null;
    if (id && id !== prevIncidentIdRef.current) {
      prevIncidentIdRef.current = id;
      setReportPassed(false);
      armedNextRef.current = false;
      setInvestigatingInEdr(false); // new incident → the EDR pause resets
      if (edrPauseCapRef.current) { clearTimeout(edrPauseCapRef.current); edrPauseCapRef.current = null; }
      try { localStorage.removeItem("soc_edr_investigated"); } catch { /* ignore */ }
      setEdrInvestigated(false);
    }
  }, [live.activeIncident]);

  // ── Mark dashboard activity (for streak + last-session), but do NOT feed the
  //    rank pool ─────────────────────────────────────────────────────────────
  // PM audit F3: the dashboard is the one ungated surface, so its practice XP
  // must not move Rank/level (which the B2B leaderboard reads). The session is
  // still recorded — appendDashboardSession() in useLiveEvents persists it for
  // history, stats, and the streak; migration 0035 keeps that XP out of
  // profiles.xp server-side. We only stamp last-session here so the optimistic
  // local rank stays in agreement with the server-authoritative total.
  const prevSessionXpRef = useRef(0);
  useEffect(() => {
    const delta = live.sessionXp - prevSessionXpRef.current;
    if (delta > 0 && typeof window !== "undefined") {
      setLastSession(new Date().toISOString());
    }
    prevSessionXpRef.current = live.sessionXp;
  }, [live.sessionXp]);

  // ── Readiness (F6): has this learner cleared any room yet? ─────────────────
  useEffect(() => {
    try {
      const rp = getRoomProgress() as Record<string, { completedAt?: string }>;
      const anyDone = Object.values(rp).some(r => !!r.completedAt);
      setRoomReady(anyDone);
    } catch { setRoomReady(true); /* fail open — never nag on corrupt data */ }
    if (typeof window !== "undefined") {
      setReadinessDismissed(localStorage.getItem("soc:dashboard-readiness-dismissed") === "1");
    }
  }, []);
  const dismissReadiness = () => {
    setReadinessDismissed(true);
    try { localStorage.setItem("soc:dashboard-readiness-dismissed", "1"); } catch { /* ignore */ }
  };

  // ── On mount: restore saved company + pick the opening modal ──────────────
  // The feed stays IDLE — no story is armed and nothing streams until the
  // student presses Start Training. That's the whole gate: no logs, and no
  // telemetry to the EDR, before the shift begins.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const saved       = localStorage.getItem(COMPANY_KEY);
    const seenWelcome  = localStorage.getItem(WELCOME_KEY);

    if (saved && saved !== "nexacorp") setSelectedCompanyId(saved);

    // Clean slate: a fresh Dashboard load has no live shift, so lock the EDR
    // and drop any stale cross-tab handoff from a previous session. This is what
    // keeps a lingering localStorage flag from leaving /edr reachable.
    setTrainingActive(false);
    try {
      localStorage.removeItem("edr_live_investigation");
      localStorage.removeItem("soc_edr_investigated");
    } catch { /* ignore */ }

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
    caughtTimesRef.current = [];
    countedIncidentIdsRef.current.clear();
    setCaughtInWindow(0);
    setWindowRemainingMs(null);
    // Picking a company does NOT start the feed — it waits for Start Training.
    // If a shift was running, end it so nothing streams for the new company
    // until the student explicitly starts again.
    setSessionStory(null);
    setInjectedStories([]);
    setSessionStartedAt(null);
    setSessionDifficulty(null);
    setTrainingActive(false);
    live.pause();
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

  // Snapshot of the live filter state — what a saved-search preset captures.
  const filterSnapshot: FilterSnapshot = {
    search, severityFilter, sourceFilter, userFilter, hostFilter, ipFilter, mitreFilter,
  };
  // Apply a saved preset back onto the filter state (and reveal row 2 if it
  // carries any advanced filter, so the applied state is actually visible).
  const applyFilterSnapshot = (s: FilterSnapshot) => {
    setSearch(s.search);
    setSeverityFilter(s.severityFilter);
    setSourceFilter(s.sourceFilter);
    setUserFilter(s.userFilter);
    setHostFilter(s.hostFilter);
    setIpFilter(s.ipFilter);
    setMitreFilter(s.mitreFilter);
    if (s.userFilter !== "all" || s.hostFilter !== "all" || s.ipFilter !== "all" || s.mitreFilter !== "all") {
      setShowAdvancedFilters(true);
    }
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
    // Persist through the facade → DB; unlocked is derived, so clearing the
    // company automatically opens the next one via the useMemo above.
    addClearedCompany(selectedCompanyId);
    setClearedCompanies(getClearedCompanies());
    setShowClearedModal(true);
  };

  const handleClearedContinue = () => {
    setShowClearedModal(false);
    if (nextCompanyId) handleSelectCompany(nextCompanyId);
  };

  /** The student caught ADVANCE_CATCHES attacks within ADVANCE_WINDOW_MS — end the
   *  shift and secure the company AUTOMATICALLY. This is the sole progression path
   *  now that "End Session" is gone: performance advances you, not a button. */
  const autoAdvanceCompany = () => {
    live.addXp(MISSION_BONUS_XP);  // reward the completed mission (session XP)
    live.endSession();          // record the run (history / streak / stats)
    live.pause();               // freeze the feed
    setSessionStartedAt(null);
    setSessionDifficulty(null);
    setTrainingActive(false);   // lock the EDR console again
    caughtTimesRef.current = [];
    countedIncidentIdsRef.current.clear();
    setCaughtInWindow(0);
    setWindowRemainingMs(null);
    try { sessionStorage.removeItem("soc_dash_session"); } catch { /* ignore */ }
    handleClearCompany();       // secure → Company-Secured modal → unlock next
  };

  // ── Start training ─────────────────────────────────────────────────────────────
  const handleStartTraining = async (difficulty: Difficulty, companyOverride?: string) => {
    // `companyOverride` is set only by the on-refresh resume (see the mount effect
    // below); normal starts use the currently-selected company.
    const company = companyOverride ?? selectedCompanyId;
    if (companyOverride && companyOverride !== selectedCompanyId) setSelectedCompanyId(companyOverride);
    // Fresh session for the current company at the chosen difficulty. A new
    // attack story is picked at RANDOM within the difficulty's complexity
    // tier and kept hidden — the objective text never reveals the attack
    // type, so the analyst must find it themselves. Easy is restricted to
    // single-host "foundation" stories (see attackStories.ts) so a student's
    // first attacks are never a full lateral-movement/credential-theft chain.
    // Await the lazy sim data (usually already preloaded when the modal opened).
    // If it can't load (offline / stale chunk), bail — simLoadFailed drives a
    // visible retry banner; loadSimData() resets so pressing Start again retries.
    let s: SimData;
    try {
      s = await ensureSim();
    } catch {
      return;
    }
    // Ensure org content finished loading so an org company resolves to its own
    // authored environment, not the generic built-in pool (fast-click race).
    const orgs = orgLoadRef.current ? await orgLoadRef.current.catch(() => orgCompanies) : orgCompanies;
    const orgMap = new Map(orgs.map(c => [c.profile.id, c]));
    const story = resolveStory(s, orgMap, company, difficulty);
    setSessionStory(story);
    setInjectedStories([story]);
    const label = difficulty[0].toUpperCase() + difficulty.slice(1);
    setScenarioObjective(`${label} session — watch the feed and report the attacks hidden in it. Catch ${ADVANCE_CATCHES} within a rolling 30-minute window to secure the company and advance — there's no time pressure, the window simply resets if it lapses. You won't be told what they are.`);
    setSessionStartedAt(Date.now());
    setSessionDifficulty(difficulty);
    setSessionElapsed(0);
    // Open the shift: this is the ONLY thing that starts the feed and unlocks
    // the EDR console. Clear any EDR-report reminder from a previous shift.
    setTrainingActive(true);
    armedNextRef.current = false;   // fresh session — next attack arms only after the first report
    caughtTimesRef.current = [];    // fresh catch window for the auto-advance rule
    countedIncidentIdsRef.current.clear();
    setCaughtInWindow(0);
    setWindowRemainingMs(null);
    try {
      localStorage.removeItem("soc_edr_investigated");
      localStorage.removeItem("edr_live_investigation");
    } catch { /* ignore */ }
    setEdrInvestigated(false);
    live.reset(resolveEvents(s, orgMap, company), story);
    // L-09: remember the active shift so a page refresh resumes it instead of
    // dropping the feed back to an idle 0-event dashboard. Session-scoped: it
    // lives only for this tab and is cleared when the shift is secured.
    try { sessionStorage.setItem("soc_dash_session", JSON.stringify({ c: company, d: difficulty })); } catch { /* ignore */ }
  };

  // L-09: on a page refresh mid-shift, resume the session instead of dropping the
  // analyst back to an idle 0-event feed. Runs once on mount; the marker is written
  // by handleStartTraining and cleared when a shift is secured.
  const resumedRef = useRef(false);
  useEffect(() => {
    if (resumedRef.current) return;
    resumedRef.current = true;
    let saved: { c?: string; d?: Difficulty } | null = null;
    try {
      const raw = sessionStorage.getItem("soc_dash_session");
      if (raw) saved = JSON.parse(raw);
    } catch { saved = null; }
    if (saved?.c && (saved.d === "easy" || saved.d === "medium" || saved.d === "hard")) {
      void handleStartTraining(saved.d, saved.c);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /**
   * Dismiss the positive "Learning Moment" debrief and CONTINUE the shift. This
   * is never a fail: no XP is clawed back and the session is not halted. We
   * clear the debrief, resume streaming, and arm the next attack (after a short
   * breather) so the analyst keeps practising with the pattern fresh in mind.
   */
  const handleContinueFromDebrief = async () => {
    live.clearMissedAttack();
    live.dismissIncident();
    if (!armedNextRef.current) {
      armedNextRef.current = true;
      const s = await ensureSim();
      const nextStory = resolveStory(s, orgCompanyMap, selectedCompanyId, sessionDifficulty ?? undefined);
      setSessionStory(nextStory);
      setInjectedStories(prev => [...prev, nextStory]);
      live.startStory(nextStory, 120_000 + Math.floor(Math.random() * 60_000)); // 2-3 min breather
    }
    live.resume(); // the debrief paused the feed; pick the shift back up
  };

  // ── Report ⇄ feed pause/resume ────────────────────────────────────────────
  /** Open the incident report — auto-pause the live feed while they write. */
  const openReport = () => {
    if (live.isStreaming) { live.pause(); setPausedForReport(true); }
    setShowReportModal(true);
  };
  /** Close the report — if we paused the feed for it, ask before resuming. */
  const closeReport = () => {
    setShowReportModal(false);
    if (pausedForReport) setShowResumePrompt(true);
  };
  const resumeShift = () => { live.resume(); setPausedForReport(false); setShowResumePrompt(false); };
  const stayPaused  = () => { setPausedForReport(false); setShowResumePrompt(false); };

  // Tick the session clock once a second while a session is running. The same
  // tick maintains the auto-advance window: it rolls off catches older than
  // ADVANCE_WINDOW_MS (so the count can drop on its own) and computes the time
  // left to reach the next catch before the oldest one expires.
  useEffect(() => {
    if (sessionStartedAt === null) return;
    const id = setInterval(() => {
      const now = Date.now();
      setSessionElapsed(Math.floor((now - sessionStartedAt) / 1000));
      const kept = caughtTimesRef.current.filter(t => now - t <= ADVANCE_WINDOW_MS);
      if (kept.length !== caughtTimesRef.current.length) {
        caughtTimesRef.current = kept;
        setCaughtInWindow(kept.length);
      }
      setWindowRemainingMs(kept.length > 0 ? Math.max(0, kept[0] + ADVANCE_WINDOW_MS - now) : null);
    }, 1000);
    return () => clearInterval(id);
  }, [sessionStartedAt]);

  const sessionClock = `${String(Math.floor(sessionElapsed / 60)).padStart(2, "0")}:${String(sessionElapsed % 60).padStart(2, "0")}`;
  // Countdown to the oldest catch expiring — the deadline to reach the next catch.
  const windowClock = windowRemainingMs != null
    ? `${String(Math.floor(windowRemainingMs / 60000)).padStart(2, "0")}:${String(Math.floor((windowRemainingMs % 60000) / 1000)).padStart(2, "0")}`
    : null;

  // Is the viewport wide enough to show the console and the report drawer
  // side by side? Tracked in state (not a Tailwind breakpoint class) because
  // the shift is applied as an inline pixel value — see the wrapper below.
  const [isWideViewport, setIsWideViewport] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const update = () => setIsWideViewport(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);

  const handleXpAward = (_delta: number) => {
    // Stub — AttackChainBoard requires an onXpAward prop but doesn't currently
    // award XP itself; it's a read-only reconstruction view after a catch.
  };

  return (
    /* While the incident-report drawer is open the whole console shifts left by
       the drawer's width instead of sitting underneath it. Overlaying still hid
       the right-hand table columns (LEVEL / RULE ID) exactly when the analyst
       needs them to quote evidence. Pushing re-flows the feed into the
       remaining space so NO log data is ever covered. Only from lg up — below
       that the drawer is full-width and side-by-side isn't possible anyway. */
    <div
      className="transition-[padding] duration-300 ease-out"
      style={{ paddingRight: showReportModal && isWideViewport ? 480 : 0 }}
    >
      {showWelcome && <SOCWelcomeModal onStart={handleCloseWelcome} onTakeTour={handleTakeTour} />}

      {showCompanySelector && (
        <CompanySelector
          currentId={selectedCompanyId}
          onSelect={handleSelectCompany}
          onClose={localStorage.getItem(COMPANY_KEY) ? () => setShowCompanySelector(false) : undefined}
          unlockedIds={[...unlockedCompanies, ...orgCompanyProfiles.map(c => c.id)]}
          clearedIds={clearedCompanies}
          extraCompanies={orgCompanyProfiles}
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
            {/* Pivot from the SIEM feed into the EDR console — the Falcon motion
                of alert → endpoint execution details. Present for the whole shift
                so it's always findable; it stays MUTED/disabled until the attack
                actually raises endpoint alerts, then lights up cyan with a
                pulsing count badge. Opens the EDR in a new tab (SIEM + EDR side by
                side). Only rendered while a shift is running. */}
            {sessionStartedAt !== null && (
              <a
                href={edrAlertCount > 0 ? "/edr?case=live" : undefined}
                target="_blank"
                rel="noopener"
                onClick={() => {
                  if (edrAlertCount > 0 && liveEdrInvestigation && typeof window !== "undefined") {
                    localStorage.setItem("edr_live_investigation", JSON.stringify(liveEdrInvestigation));
                    // Pause the response clock (and defer any "missed" verdict)
                    // while they investigate in EDR. Safety cap resumes it after
                    // 20 min so an abandoned EDR tab can't freeze it forever.
                    setInvestigatingInEdr(true);
                    if (edrPauseCapRef.current) clearTimeout(edrPauseCapRef.current);
                    edrPauseCapRef.current = setTimeout(() => setInvestigatingInEdr(false), 1_200_000);
                  }
                }}
                className={cn(
                  "relative flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs font-semibold transition",
                  edrAlertCount > 0
                    ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-200 hover:bg-cyber-500/20"
                    : "cursor-not-allowed border-border bg-bg text-slate-500",
                )}
                aria-disabled={edrAlertCount === 0}
                title={edrAlertCount > 0
                  ? `${edrAlertCount} EDR alert${edrAlertCount > 1 ? "s" : ""} on the endpoint — investigate this attack (opens the EDR console)`
                  : "No endpoint alerts yet — this lights up when the attack reaches an endpoint"}
              >
                <Cpu className="h-3.5 w-3.5" />
                Investigate in EDR
                {edrAlertCount > 0 && (
                  <span className="absolute -top-2 -right-2 flex h-5 min-w-[1.25rem] animate-pulse items-center justify-center rounded-full bg-severity-critical px-1 text-[10px] font-bold text-white shadow ring-2 ring-bg-elevated">
                    {edrAlertCount}
                  </span>
                )}
              </a>
            )}
            {/* Report Incident — the key action, and the only place the analyst
                is graded. Solid CTA throughout; no pulse/hint tied to whether
                they've "caught" anything — that would leak the answer. */}
            <button
              id="report-incident-btn"
              onClick={openReport}
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
            <Button variant="primary" size="sm" onClick={() => { loadSimData().catch(() => {}); setShowTrainingModal(true); }}>
              <Target className="h-4 w-4" /> Start Training
            </Button>
          </div>
        }
      />

      <div className="container mx-auto max-w-[1600px] px-6 py-6 space-y-6">

        {/* Readiness signal (F6) — soft, dismissible, non-blocking. Shown only to
            a learner who has cleared 0 rooms: the live feed is real production
            telemetry with no scaffolding, so we point them at the graded path
            first without locking them out. */}
        {!roomReady && !readinessDismissed && (
          <div className="flex items-start gap-3 rounded-lg border border-cyber-500/30 bg-cyber-500/5 px-4 py-3">
            <GraduationCap className="mt-0.5 h-5 w-5 shrink-0 text-cyber-300" />
            <div className="flex-1 text-sm">
              <p className="font-semibold text-white">New here? Start with the fundamentals.</p>
              <p className="mt-0.5 text-slate-400">
                This is a live feed of real production logs — no hints. You&apos;ll get far more out of it
                after a few graded rooms build the basics. You can still explore now.
              </p>
              <Link href="/rooms" className="mt-2 inline-flex items-center gap-1.5 text-xs font-semibold text-cyber-300 hover:text-cyber-200">
                <BookOpen className="h-3.5 w-3.5" /> Go to Learning Rooms
              </Link>
            </div>
            <button onClick={dismissReadiness} aria-label="Dismiss" className="shrink-0 rounded p-1 text-slate-500 hover:text-slate-300">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

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
            <BookOpen className="h-3.5 w-3.5 text-slate-400" />
            <span className="font-semibold text-white">Companies</span>
            <span className="font-mono text-sm font-bold text-neon-purple">{clearedCompanies.length}/{COMPANY_ORDER.length}</span>
          </span>
          {/* Reflected from the EDR console: a host contained there shows as
              contained here too — one shared response state across both surfaces. */}
          {edrContained.length > 0 && (
            <span
              className="flex items-center gap-1.5 rounded-full border border-neon-amber/40 bg-neon-amber/10 px-2.5 py-1 text-[11px] font-semibold text-neon-amber"
              title={`Contained in EDR: ${edrContained.join(", ")}`}
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              {edrContained.length === 1 ? `${edrContained[0]} contained in EDR` : `${edrContained.length} hosts contained in EDR`}
            </span>
          )}
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
              {/* Progress toward the auto-advance rule: catch 2 attacks in a
                  rolling 30-min window. Framed as positive progress, not time
                  pressure — if the window lapses the count just resets, no penalty
                  (consistent with the no-fail debrief philosophy elsewhere). */}
              <span
                className="rounded border border-cyber-500/40 bg-cyber-500/10 px-1.5 py-px text-[10px] font-bold uppercase tracking-wider text-cyber-300"
                title={`Catch ${ADVANCE_CATCHES} attacks within a rolling 30-minute window to secure the company and advance — no rush, the window just resets if it lapses`}
              >
                Caught {Math.min(caughtInWindow, ADVANCE_CATCHES)}/{ADVANCE_CATCHES}
              </span>
              {/* Explicit, calm status: how many more and how long left in the
                  current rolling window. Neutral cyber tone (not alarming amber). */}
              {caughtInWindow > 0 && caughtInWindow < ADVANCE_CATCHES && windowClock && (
                <span
                  className="flex items-center gap-1 rounded border border-cyber-500/30 bg-cyber-500/5 px-1.5 py-px font-mono text-[10px] font-semibold text-cyber-300/90"
                  title="One more catch within this window secures the company. If it lapses the count just resets — no penalty."
                >
                  <Clock className="h-3 w-3" /> {ADVANCE_CATCHES - Math.min(caughtInWindow, ADVANCE_CATCHES)} more · {windowClock} left
                </span>
              )}
            </span>
          ) : (
            <span className="ml-auto flex items-center gap-2 text-xs text-slate-400">
              <span className="h-2 w-2 rounded-full bg-slate-600" />
              No active session — press
              <span className="font-semibold text-slate-400">Start Training</span>
            </span>
          )}
        </div>

        {/* Sim-data load failure — visible retry instead of a silent dead-end.
            loadSimData() resets its cache on failure, so Retry genuinely re-attempts. */}
        {simLoadFailed && (
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-severity-critical/50 bg-severity-critical/10 px-5 py-3">
            <Siren className="h-4 w-4 shrink-0 text-severity-critical" />
            <p className="text-sm text-slate-200">
              Couldn&apos;t load the training data — check your connection and try again.
            </p>
            <button
              onClick={() => { setSimLoadFailed(false); loadSimData().then(setSim).catch(() => setSimLoadFailed(true)); }}
              className="ml-auto rounded-md bg-neon-purple px-3 py-1.5 text-xs font-bold text-white transition hover:brightness-110"
            >
              Retry
            </button>
          </div>
        )}

        {/* Scenario objective banner */}
        {scenarioObjective && (
          <div className="flex items-center gap-3 rounded-lg border border-neon-purple/30 bg-neon-purple/5 px-5 py-3">
            <Target className="h-4 w-4 shrink-0 text-neon-purple" />
            <p className="text-sm text-slate-200">{scenarioObjective}</p>
            <button onClick={() => setScenarioObjective(null)} className="ml-auto text-slate-400 hover:text-slate-300">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* Don't-forget-the-report reminder — shows once the student has
            investigated on the endpoint but not yet filed a passing report. */}
        {edrInvestigated && !reportPassed && (
          <div className="flex flex-wrap items-center gap-3 rounded-lg border border-neon-amber/40 bg-neon-amber/10 px-5 py-3">
            <FileText className="h-4 w-4 shrink-0 text-neon-amber" />
            <p className="text-sm text-slate-200">
              You investigated this attack on the endpoint — <span className="font-semibold text-white">now file your incident report</span> to close the ticket.
            </p>
            <button
              onClick={openReport}
              className="ml-auto rounded-md bg-neon-purple px-3 py-1.5 text-xs font-bold text-white transition hover:brightness-110"
            >
              Report Incident
            </button>
          </div>
        )}

        {/* Learning-Moment debrief — a POSITIVE teaching pause, never a penalty.
            When an attack completes uncaught (after a generous grace, and never
            mid-investigation), the feed pauses behind this modal so the analyst
            reads the pattern; dismissing it resumes the shift and arms the next
            attack. No "failed", no "training stopped", no red alarm — instructive
            blue/cyber tone, one clear "Continue the shift" action. */}
        {live.missedAttack && live.missedIncident && (() => {
          const debrief = live.missedIncident;
          const ids = new Set(live.activeIncident?.eventIds ?? []);
          // live.events is newest-first; sort chronologically and keep the
          // EARLIEST six so the opening moves (the ones worth learning to catch)
          // read top-to-bottom.
          const teachingEvents = live.events
            .filter(e => ids.has(e.id))
            .sort((a, b) => new Date(a.ts).getTime() - new Date(b.ts).getTime())
            .slice(0, 6);
          return (
            <div
              className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm"
              role="dialog" aria-modal="true" aria-labelledby="learning-moment-title"
            >
              <div className="max-h-[88vh] w-full max-w-2xl overflow-y-auto rounded-2xl border border-cyber-500/40 bg-bg-elevated shadow-2xl shadow-cyber-500/10">
                <div className="h-1 w-full bg-gradient-to-r from-cyber-500 via-neon-purple to-neon-green" />

                <div className="border-b border-border px-7 py-7 text-center">
                  <span className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-cyber-500/10 ring-2 ring-cyber-500/40">
                    <GraduationCap className="h-8 w-8 text-cyber-300" />
                  </span>
                  <p className="mt-4 text-[11px] font-semibold uppercase tracking-[0.2em] text-cyber-300">Learning Moment</p>
                  <h2 id="learning-moment-title" className="mt-2 text-2xl font-bold text-white">
                    One slipped past
                  </h2>
                  <p className="mx-auto mt-3 max-w-lg text-sm leading-relaxed text-slate-300">
                    This attack unfolded without a report. Here&apos;s the pattern so you catch it next
                    time — that&apos;s how analysts sharpen.
                  </p>
                  <p className="mt-4 inline-block rounded-full bg-neon-green/10 px-3 py-1 text-xs font-medium text-neon-green">
                    No points lost — the shift keeps going
                  </p>
                </div>

                <div className="space-y-4 px-7 py-6">
                  {/* What it was */}
                  <div className="rounded-lg border border-cyber-500/20 bg-cyber-500/5 px-4 py-3">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-cyber-300">What it was</p>
                    <p className="mt-1 text-sm font-semibold text-white">{debrief.title}</p>
                    {debrief.techniques.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1.5">
                        {debrief.techniques.map(t => (
                          <span key={t} className="inline-flex items-center rounded border border-neon-purple/30 bg-neon-purple/10 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-neon-purple">
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* The tell */}
                  <div className="rounded-lg border border-neon-amber/20 bg-neon-amber/5 px-4 py-3">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-neon-amber">The tell to watch for next time</p>
                    <p className="mt-1 text-sm leading-relaxed text-slate-200">{debrief.tell}</p>
                  </div>

                  {/* How it unfolded */}
                  {teachingEvents.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-widest text-slate-400">How it unfolded</p>
                      <ol className="mt-3 space-y-3">
                        {teachingEvents.map((e, i) => (
                          <li key={e.id} className="flex gap-3">
                            <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-cyber-500/15 font-mono text-[10px] text-cyber-300">
                              {i + 1}
                            </span>
                            <div className="min-w-0">
                              <span className="font-mono text-[11px] text-slate-400">{new Date(e.ts).toLocaleTimeString("en-GB")}</span>
                              <p className="text-xs leading-relaxed text-slate-300">{e.description ?? e.displayDescription}</p>
                            </div>
                          </li>
                        ))}
                      </ol>
                    </div>
                  )}
                </div>

                <div className="border-t border-border px-7 py-5">
                  <Button variant="primary" size="lg" className="w-full" onClick={handleContinueFromDebrief}>
                    <Play className="mr-2 h-4 w-4" /> Continue the shift
                  </Button>
                </div>
              </div>
            </div>
          );
        })()}

        {/* Analyst workflow — persistent "what do I do now?" strip */}
        <WorkflowGuide reportPassed={reportPassed} />

        {/* Tiered, opt-in nudges for a stuck analyst — only while a shift runs.
            Methodology only; never reveals the IOC/verdict/technique (HintPanel). */}
        {sessionStartedAt !== null && (
          <HintPanel
            story={sessionStory}
            resetKey={live.activeIncident?.id ?? sessionStory?.id ?? null}
          />
        )}

        {/* Live Event Feed */}
        <div className="flex gap-4 items-start">
          <div className="min-w-0 flex-1">
          <Card padded={false} className="overflow-hidden">
          {/* Feed header */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3">
            <div className="flex items-center gap-3">
              {/* Pulsing green only while the feed is actually streaming; a
                  static amber dot (no ping) when paused, so the indicator never
                  claims "live" while stopped. */}
              <span className="relative flex h-2 w-2" title={live.isStreaming ? "Live — streaming" : "Paused"}>
                {live.isStreaming && (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-neon-green opacity-75" />
                )}
                <span className={cn(
                  "relative inline-flex h-2 w-2 rounded-full",
                  live.isStreaming ? "bg-neon-green" : "bg-neon-amber"
                )} />
              </span>
              <div>
                <h3 className="text-sm font-semibold text-white">Live Event Feed</h3>
                <p className="text-[10px] text-slate-400">Click a row to expand and read the full log</p>
              </div>
            </div>

            {/* Controls */}
            <div className="flex items-center gap-2">
              {/* Search */}
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
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
            <Filter className="h-3.5 w-3.5 shrink-0 text-slate-400" />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">Level:</span>

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
                      : "border-border text-slate-400 hover:border-border-strong hover:text-slate-300"
                  )}
                >
                  {lv === "all" ? "All" : lv === "low" ? "1-3 Low" : lv === "medium" ? "4-6 Med" : "7-10 High"}
                </button>
              ))}
            </div>

            <span className="text-[10px] text-slate-400">|</span>

            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="h-6 rounded border border-border bg-bg px-2 text-[10px] text-slate-300 focus:border-cyber-500/50 focus:outline-none"
            >
              {resolveSources(selectedCompanyId).map(s => (
                <option key={s.value} value={s.value}>{s.label}</option>
              ))}
            </select>

            <button
              onClick={() => setShowAdvancedFilters(v => !v)}
              className={cn(
                "ml-auto rounded border px-2 py-0.5 text-[10px] font-semibold transition",
                advancedFilterCount > 0
                  ? "border-cyber-500/50 bg-cyber-500/10 text-cyber-300"
                  : "border-border text-slate-400 hover:text-slate-300 hover:border-border-strong"
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
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">User</span>
              <select
                aria-label="Filter events by user"
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
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">Host</span>
              <select
                aria-label="Filter events by host"
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
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">IP</span>
              <select
                aria-label="Filter events by source IP"
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
              <span className="text-[9px] font-semibold uppercase tracking-wider text-slate-400">MITRE</span>
              <select
                aria-label="Filter events by MITRE technique"
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

            <span className="ml-auto text-[10px] text-slate-400 font-mono">
              {filterOptions.users.length}u · {filterOptions.hosts.length}h · {filterOptions.ips.length} IPs
            </span>
          </div>
          )}

          {/* Saved searches — named presets over the query + dropdown filters */}
          <SavedSearches current={filterSnapshot} onApply={applyFilterSnapshot} />

          <SiemStats
            events={live.events}
            attackTimerSeconds={live.attackTimerSeconds}
            avgCatchMs={live.avgCatchMs}
            slaPaused={(showReportModal || investigatingInEdr) && live.attackTimerSeconds != null}
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
        // Ground truth = every GENUINE attack the student actually saw this
        // session — the injected story PLUS any other real attack event that
        // surfaced in the feed. Grading only off the picked story used to punish
        // correct analysis: a student who spotted a different (but equally real)
        // attack chain in the noise, and quoted its true IOCs, had those IOCs
        // scored as "fabricated" because they weren't in the one picked story.
        // FP decoys (it_verify_result / fp_explanation / expected_verdict:"fp")
        // are excluded so they never become gradeable "attacks".
        const feedAttackEvents = live.events.filter(e =>
          !!e.mitre_technique &&
          (e.severity === "high" || e.severity === "critical") &&
          !e.it_verify_result && !e.fp_explanation && e.expected_verdict !== "fp"
        );
        const groundTruthEvents = [...injectedStories.flatMap(s => s.events), ...feedAttackEvents];
        const storyMitre = Array.from(new Set([
          ...injectedStories.flatMap(s => s.mitre),
          ...feedAttackEvents.map(e => e.mitre_technique).filter((m): m is string => !!m),
        ]));
        const storyTitle = injectedStories.map(s => s.title).join(" + ") || null;
        // Indicators the grader uses to verify the student cited real evidence
        // and to catch genuinely fabricated data (a hostname that never appears).
        const realIndicators = extractIndicators(groundTruthEvents);
        // Full serialized evidence (raw blocks included) so the grader's
        // fabrication check treats ANY IP/email/hash the student cites that is
        // visible in a log — including MD5/SHA1, private host IPs, and vendor-keyed
        // raw fields the discrete extractIndicators list doesn't enumerate — as
        // real, never "fabricated". Mirrors the scenario grader's eventsBlob.
        const evidenceText = JSON.stringify(groundTruthEvents);
        // Decoys the student saw this session — benign events carrying a written
        // fp_explanation that, until now, was authored but never surfaced anywhere
        // in the UI. Shown only AFTER a passing report (see the modal) as a
        // "why these were false positives" debrief. Deduped by explanation text
        // (the same decoy type recurs in the feed) and capped so the modal stays
        // readable.
        const decoysSeen = (() => {
          const seen = new Set<string>();
          const out: { label: string; source: string; fp_explanation: string }[] = [];
          for (const e of live.events) {
            if (!e.fp_explanation || seen.has(e.fp_explanation)) continue;
            seen.add(e.fp_explanation);
            const label = (e.description?.split(/[.—]/)[0]?.trim().slice(0, 90))
              || e.event_type || e.source;
            out.push({ label, source: e.source, fp_explanation: e.fp_explanation });
          }
          return out.slice(0, 6);
        })();
        return (
          <IncidentReportModal
            companyName={selectedCompany.name}
            companyId={selectedCompanyId}
            realIndicators={realIndicators}
            evidenceText={evidenceText}
            attackTitle={storyTitle}
            attackMitreTechniques={storyMitre}
            decoys={decoysSeen}
            // Response-time coaching data. Prefer the recorded response time; if
            // the report is filed before an explicit catch, fall back to the
            // current elapsed clock (seconds → ms). Coaching only — not graded.
            responseMs={live.lastResponseMs ?? (live.attackTimerSeconds != null ? live.attackTimerSeconds * 1000 : null)}
            responseTargetSeconds={live.responseTargetSeconds}
            onClose={closeReport}
            onPassed={async (score: number) => {
              setReportPassed(true);
              // Report filed — clear the EDR "don't forget" reminder.
              try { localStorage.removeItem("soc_edr_investigated"); } catch { /* ignore */ }
              setEdrInvestigated(false);

              // Dedup: count each incident exactly once. The modal's submit stays
              // interactive after a pass, so a re-submitted passing report must not
              // double-count toward auto-advance, re-award XP, or re-arm an attack.
              const incidentId = live.activeIncident?.id ?? null;
              // No active incident to attribute the catch to (e.g. the report modal
              // was left open until this incident rolled out and none is live) —
              // nothing to reward, count, or re-arm. Guards a stale re-submit from
              // re-awarding XP when the dedup key (incident.id) is absent.
              if (!incidentId) return;
              if (countedIncidentIdsRef.current.has(incidentId)) return;
              countedIncidentIdsRef.current.add(incidentId);

              // A passing report IS the catch — register it for real. Without
              // this, markCaught() was never called from anywhere: the SLA
              // never cleared on a correct report, avgCatchMs/attacksCaughtCount
              // stayed permanently empty, and the miss-timer would still fire
              // later and count a genuinely-caught attack as missed.
              const caughtIds = live.activeIncident?.eventIds ?? [];
              if (caughtIds.length > 0) live.markCaught(caughtIds[0]);

              // Reward the catch with SESSION XP proportional to the report score
              // so the XP chip moves on every good report (was: 0 until the mission
              // bonus at advance). Session-scoped via live.addXp — per PM audit F3 /
              // migration 0035 the dashboard's XP never touches rank/profiles.xp.
              live.addXp(Math.max(25, Math.round(score * 1.5)));

              // Auto-advance rule: only a real incident counts. Record this catch's
              // time, keep only those inside the rolling window, and if the student
              // has now caught ADVANCE_CATCHES within ADVANCE_WINDOW_MS, secure the
              // company automatically and stop.
              if (incidentId) {
                const now = Date.now();
                caughtTimesRef.current = [...caughtTimesRef.current, now].filter(t => now - t <= ADVANCE_WINDOW_MS);
                setCaughtInWindow(caughtTimesRef.current.length);
                setWindowRemainingMs(caughtTimesRef.current.length > 0 ? Math.max(0, caughtTimesRef.current[0] + ADVANCE_WINDOW_MS - now) : null);
                if (caughtTimesRef.current.length >= ADVANCE_CATCHES && !clearedCompanies.includes(selectedCompanyId)) {
                  autoAdvanceCompany();
                  return; // advancing — don't arm another attack for this (now secured) company
                }
              }
              // ONE incident at a time: only now — with the current one reported —
              // do we arm the NEXT attack, and only once per incident. It lands
              // after a short breather so the student is never juggling two.
              if (!armedNextRef.current) {
                armedNextRef.current = true;
                const s = await ensureSim();
                const nextStory = resolveStory(s, orgCompanyMap, selectedCompanyId, sessionDifficulty ?? undefined);
                setSessionStory(nextStory);
                setInjectedStories(prev => [...prev, nextStory]);
                live.startStory(nextStory, 120_000 + Math.floor(Math.random() * 60_000)); // 2-3 min
              }
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

      {/* ── Company Cleared Modal ──────────────────────────────────────── */}
      {showClearedModal && (
        <CompanyClearedModal
          clearedCompanyName={selectedCompany.name}
          nextCompanyName={nextCompany?.name ?? null}
          xpAwarded={MISSION_BONUS_XP}
          attacksCaught={ADVANCE_CATCHES}
          onContinue={handleClearedContinue}
        />
      )}

      {/* ── Resume-shift prompt — after closing the report, the feed is still
          paused; ask before resuming so the analyst isn't dropped back into a
          moving feed unexpectedly. ─────────────────────────────────────────── */}
      {showResumePrompt && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-labelledby="resume-shift-title">
          <div className="w-full max-w-sm rounded-2xl border border-border bg-bg-elevated p-6 shadow-2xl">
            <div className="flex items-center gap-3">
              <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-neon-green/30 bg-neon-green/10">
                <Play className="h-5 w-5 text-neon-green" />
              </span>
              <div>
                <h2 id="resume-shift-title" className="text-base font-bold text-white">Resume the shift?</h2>
                <p className="mt-0.5 text-xs text-slate-400">The live feed is paused while you wrote the report.</p>
              </div>
            </div>
            <div className="mt-5 flex justify-end gap-2">
              <button onClick={stayPaused} className="rounded-md border border-border px-3 py-2 text-xs font-semibold text-slate-300 transition hover:bg-white/5">
                Stay paused
              </button>
              <button onClick={resumeShift} className="flex items-center gap-1.5 rounded-md bg-neon-green px-4 py-2 text-xs font-bold text-bg transition hover:bg-neon-green/90">
                <Play className="h-3.5 w-3.5" /> Continue
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
}
