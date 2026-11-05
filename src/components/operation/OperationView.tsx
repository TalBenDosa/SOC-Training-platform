"use client";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { AnimatePresence, motion } from "framer-motion";
import {
  ArrowLeft, Shield, ShieldOff, KeyRound, Star, Trophy, RotateCcw, Eye, ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { TaskPlayer } from "@/components/rooms/TaskPlayer";
import { getRoomProgress } from "@/lib/storage/progress";
import { RoomCelebration, CountUp, roomRank } from "@/components/rooms/Celebration";
import { mechanicFor, type BriefingLab, type RoomExperience, type Station } from "@/lib/rooms/experience";
import type { SanitizedRoom, SanitizedRoomTask } from "@/lib/rooms/sanitize";
import type { TaskTelemetryEntry } from "@/lib/useTaskTelemetry";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { HubStation } from "./board/types";
import { LockTerminal } from "./mechanics/LockTerminal";
import { TriageDesk } from "./mechanics/TriageDesk";
import { EvidenceBoard } from "./mechanics/EvidenceBoard";
import { VaultKeypad } from "./mechanics/VaultKeypad";
import { IntelBriefing } from "./briefing/IntelBriefing";
import { MissionBoard, type StoryEntry } from "./board/MissionBoard";
import { StoryPlayer } from "./StoryPlayer";
import { Drill } from "./briefing/Drill";
import { StageBoard } from "./board/StageBoard";
import { CampusBoard } from "./board/CampusBoard";
import { LensBoard } from "./board/LensBoard";
import type { WorldProps } from "./scenes/common";
import type { MechanicProps } from "./shared";

const ShieldScene = dynamic(() => import("./ShieldScene"), { ssr: false });
const WORLDS: Record<string, React.ComponentType<WorldProps>> = {
  gates: dynamic(() => import("./scenes/GateScene"), { ssr: false }),
  tower: dynamic(() => import("./scenes/TowerScene"), { ssr: false }),
  network: dynamic(() => import("./scenes/NetworkScene"), { ssr: false }),
  campus: dynamic(() => import("./scenes/CampusScene"), { ssr: false }),
  city: dynamic(() => import("./scenes/CityScene"), { ssr: false }),
  datapath: dynamic(() => import("./scenes/DatapathScene"), { ssr: false }),
  socfloor: dynamic(() => import("./scenes/SocFloorScene"), { ssr: false }),
  portwall: dynamic(() => import("./scenes/PortWallScene"), { ssr: false }),
  hostcore: dynamic(() => import("./scenes/HostCoreScene"), { ssr: false }),
  fstree: dynamic(() => import("./scenes/FsTreeScene"), { ssr: false }),
  logriver: dynamic(() => import("./scenes/LogRiverScene"), { ssr: false }),
  cipherlab: dynamic(() => import("./scenes/CipherLabScene"), { ssr: false }),
  chrono: dynamic(() => import("./scenes/ChronoScene"), { ssr: false }),
  dissect: dynamic(() => import("./scenes/DissectScene"), { ssr: false }),
  idgate: dynamic(() => import("./scenes/IdGateScene"), { ssr: false }),
  specimen: dynamic(() => import("./scenes/SpecimenScene"), { ssr: false }),
  riskcore: dynamic(() => import("./scenes/RiskCoreScene"), { ssr: false }),
  patchline: dynamic(() => import("./scenes/PatchLineScene"), { ssr: false }),
  chainlinks: dynamic(() => import("./scenes/ChainLinksScene"), { ssr: false }),
  zonewall: dynamic(() => import("./scenes/ZoneWallScene"), { ssr: false }),
  blackbox: dynamic(() => import("./scenes/BlackBoxScene"), { ssr: false }),
  mindlab: dynamic(() => import("./scenes/MindLabScene"), { ssr: false }),
  sightlines: dynamic(() => import("./scenes/SightLinesScene"), { ssr: false }),
  webpath: dynamic(() => import("./scenes/WebPathScene"), { ssr: false }),
  baitshop: dynamic(() => import("./scenes/BaitShopScene"), { ssr: false }),
  orchard: dynamic(() => import("./scenes/OrchardScene"), { ssr: false }),
  evtxtape: dynamic(() => import("./scenes/EvtxTapeScene"), { ssr: false }),
  varlog: dynamic(() => import("./scenes/VarLogScene"), { ssr: false }),
  radar: dynamic(() => import("./scenes/RadarScene"), { ssr: false }),
  intake: dynamic(() => import("./scenes/IntakeScene"), { ssr: false }),
  postmark: dynamic(() => import("./scenes/PostmarkScene"), { ssr: false }),
  protostack: dynamic(() => import("./scenes/ProtoStackScene"), { ssr: false }),
  sealedbrief: dynamic(() => import("./scenes/SealedBriefScene"), { ssr: false }),
  sparekey: dynamic(() => import("./scenes/SpareKeyScene"), { ssr: false }),
  objectpipe: dynamic(() => import("./scenes/ObjectPipeScene"), { ssr: false }),
  integrityladder: dynamic(() => import("./scenes/IntegrityLadderScene"), { ssr: false }),
  matrixwall: dynamic(() => import("./scenes/MatrixWallScene"), { ssr: false }),
  domaintree: dynamic(() => import("./scenes/DomainTreeScene"), { ssr: false }),
  wazuhflow: dynamic(() => import("./scenes/WazuhFlowScene"), { ssr: false }),
  skyquery: dynamic(() => import("./scenes/SkyQueryScene"), { ssr: false }),
  noisefilter: dynamic(() => import("./scenes/NoiseFilterScene"), { ssr: false }),
  tenantcloud: dynamic(() => import("./scenes/TenantCloudScene"), { ssr: false }),
  talon: dynamic(() => import("./scenes/TalonScene"), { ssr: false }),
  storyline: dynamic(() => import("./scenes/StorylineScene"), { ssr: false }),
  detonation: dynamic(() => import("./scenes/DetonationScene"), { ssr: false }),
  nightqueue: dynamic(() => import("./scenes/NightQueueScene"), { ssr: false }),
  coldcase: dynamic(() => import("./scenes/ColdCaseScene"), { ssr: false }),
  longdistance: dynamic(() => import("./scenes/LongDistanceScene"), { ssr: false }),
  denyall: dynamic(() => import("./scenes/DenyAllScene"), { ssr: false }),
  lookup: dynamic(() => import("./scenes/LookupScene"), { ssr: false }),
  generations: dynamic(() => import("./scenes/GenerationsScene"), { ssr: false }),
  secondopinion: dynamic(() => import("./scenes/SecondOpinionScene"), { ssr: false }),
  ignoreall: dynamic(() => import("./scenes/IgnoreAllScene"), { ssr: false }),
  wirelevel: dynamic(() => import("./scenes/WireLevelScene"), { ssr: false }),
  opensesame: dynamic(() => import("./scenes/OpenSesameScene"), { ssr: false }),
};

const MAX_SHIELDS = 3;

type Phase = "briefing" | "hub" | "station" | "cleared" | "breached" | "debrief";

// Per-viewer cosmetic state (stars, Intel tokens, briefing seen). Never XP or
// progress — those live in room_progress via RoomClient. Guarded: blocked
// storage simply means the stars start fresh.
interface OpLocal { stars: Record<string, number>; tokens: number; seenBriefing: boolean; seenStory: string[]; /** Shields left in a station still in progress: leaving and coming back must not refill them. */ shields: Record<string, number> }
const opKey = (roomId: string) => `soc:operation:${roomId}`;
function readLocal(roomId: string): OpLocal {
  try {
    const raw = window.localStorage.getItem(opKey(roomId));
    if (raw) return { stars: {}, tokens: 0, seenBriefing: false, seenStory: [], shields: {}, ...JSON.parse(raw) };
  } catch { /* storage unavailable */ }
  return { stars: {}, tokens: 0, seenBriefing: false, seenStory: [], shields: {} };
}
function writeLocal(roomId: string, v: OpLocal) {
  try { window.localStorage.setItem(opKey(roomId), JSON.stringify(v)); } catch { /* storage unavailable */ }
}

function webglAvailable(): boolean {
  try {
    const c = document.createElement("canvas");
    return !!(c.getContext("webgl2") || c.getContext("webgl"));
  } catch { return false; }
}

export interface OperationViewProps {
  room: SanitizedRoom;
  /** The learner's stored progress has landed (signed-in progress arrives after first paint). */
  progressReady: boolean;
  /** Wrong graded answers per task, from the server: stars on a device with no local record. */
  wrongByTask?: Record<string, number>;
  experience: RoomExperience;
  currentTaskIndex: number;
  completedTaskIds: Set<string>;
  scorePct: number;
  passPct: number;
  totalXpEarned: number;
  showCompletion: boolean;
  showFailure: boolean;
  missedCount: number;
  prevLogEvent?: TelemetryEvent;
  nextRoom: { id: string; title: string; started: boolean } | null;
  onTaskComplete: (xp: number, telemetry?: TaskTelemetryEntry, passCredit?: number) => void;
  goToTask: (idx: number) => void;
  /** Re-open tasks for a station replay / reset (XP is best-of, never clawed back). */
  reopenTasks: (ids: string[]) => void;
  onReviewMissed: () => void;
  onStartReview: () => void;
  onNavigate: (href: string) => void;
}

export function OperationView(p: OperationViewProps) {
  const { room, experience, completedTaskIds, currentTaskIndex } = p;
  const [local, setLocal] = useState<OpLocal>({ stars: {}, tokens: 0, seenBriefing: true, seenStory: [], shields: {} });
  const [story, setStory] = useState<StoryEntry | null>(null);
  const [phase, setPhase] = useState<Phase>("hub");
  const [activeId, setActiveId] = useState<string | null>(null);
  const [shields, setShields] = useState(MAX_SHIELDS);
  const [slow, setSlow] = useState(false);
  const [taskKey, setTaskKey] = useState(0);
  const [lastStars, setLastStars] = useState(0);
  const [has3d, setHas3d] = useState(true);
  const [reducedMotion, setReducedMotion] = useState(false);
  const initRef = useRef(false);
  const panelRef = useRef<HTMLDivElement>(null);

  // Each new task starts at the top of the station panel.
  useEffect(() => { panelRef.current?.scrollTo({ top: 0 }); }, [currentTaskIndex, taskKey]);

  const indexOf = useMemo(() => new Map(room.tasks.map((t, i) => [t.id, i])), [room.tasks]);
  const active: Station | undefined = experience.stations.find(s => s.id === activeId);

  const updateLocal = useCallback((fn: (v: OpLocal) => OpLocal) => {
    setLocal(prev => { const next = fn(prev); writeLocal(room.id, next); return next; });
  }, [room.id]);

  // First paint: environment checks + where to start.
  useEffect(() => {
    // Wait for the learner's real progress: before it lands every room looks untouched,
    // which replayed the briefing film on rooms already finished.
    if (initRef.current || !p.progressReady) return;
    initRef.current = true;
    const l = readLocal(room.id);
    const started = completedTaskIds.size > 0 || (getRoomProgress()[room.id]?.completedTaskIds?.length ?? 0) > 0;
    setLocal(l);
    setHas3d(webglAvailable());
    setReducedMotion(window.matchMedia?.("(prefers-reduced-motion: reduce)").matches ?? false);
    if (p.showCompletion || p.showFailure) setPhase("debrief");
    else if (!started && !l.seenBriefing) {
      setPhase("briefing");
      const intro = experience.story?.intro;
      if (intro && !l.seenStory.includes("intro")) setStory({ key: "intro", label: "Briefing film", clip: intro });
    }
    else setPhase("hub");
  }, [room.id, p.progressReady, p.showCompletion, p.showFailure, completedTaskIds.size, experience.story]);

  // Story films: what this viewer has unlocked, in mission order, for replay.
  const stories: StoryEntry[] = useMemo(() => {
    const out: StoryEntry[] = [];
    const s = experience.story;
    if (s?.intro) out.push({ key: "intro", label: "Briefing film", clip: s.intro });
    let chapter = 1;
    for (const st of experience.stations) {
      const clip = s?.afterStation?.[st.id];
      if (clip) out.push({ key: st.id, label: `Chapter ${++chapter}`, clip });
    }
    return out;
  }, [experience.story, experience.stations]);
  // Replayable: the intro, every chapter whose station is cleared (a learner who
  // finished the room before its films existed still gets them), and anything seen.
  const watched = stories.filter(e =>
    e.key === "intro" || local.seenStory.includes(e.key) ||
    !!experience.stations.find(st => st.id === e.key)?.taskIds.every(id => completedTaskIds.has(id)));

  function closeStory() {
    if (story) updateLocal(v => ({
      ...v,
      seenStory: v.seenStory.includes(story.key) ? v.seenStory : [...v.seenStory, story.key],
      // Watching or skipping the briefing film counts as having been briefed.
      seenBriefing: v.seenBriefing || story.key === "intro",
    }));
    setStory(null);
  }

  // React only to the room's result CHANGING (hydration landing, a replay
  // finishing, "revisit missed" re-opening tasks) — so "Back to the floor" from
  // the debrief is not immediately bounced back.
  useEffect(() => {
    if (p.showCompletion || p.showFailure) setPhase(ph => (ph === "hub" || ph === "briefing" ? "debrief" : ph));
    else setPhase(ph => (ph === "debrief" ? "hub" : ph));
  }, [p.showCompletion, p.showFailure]);

  const stationDone = useCallback((s: Station) => s.taskIds.every(id => completedTaskIds.has(id)), [completedTaskIds]);

  const hubStations: HubStation[] = useMemo(() => {
    let blocked = false;
    return experience.stations.map(s => {
      const done = s.taskIds.filter(id => completedTaskIds.has(id)).length;
      const cleared = done === s.taskIds.length;
      const status = cleared ? "cleared" : blocked ? "locked" : "open";
      if (!cleared) blocked = true;
      return {
        id: s.id, label: s.label, boss: s.boss, building: s.building, status,
        // This device's best run, else what the server's graded answers show (another device).
        stars: cleared ? Math.max(1, local.stars[s.id] ?? MAX_SHIELDS - s.taskIds.reduce((n, t) => n + (p.wrongByTask?.[t] ?? 0), 0)) : 0,
        progress: `${done}/${s.taskIds.length}`,
      } as HubStation;
    });
  }, [experience.stations, completedTaskIds, local.stars, p.wrongByTask]);

  // Station cleared → score it from the shields left.
  useEffect(() => {
    if (phase !== "station" || !active) return;
    if (stationDone(active)) {
      const stars = Math.max(1, shields - (slow ? 1 : 0));
      setLastStars(stars);
      updateLocal(v => {
        const { [active.id]: _cleared, ...rest } = v.shields;
        void _cleared;
        return { ...v, shields: rest, stars: { ...v.stars, [active.id]: Math.max(v.stars[active.id] ?? 0, stars) } };
      });
      setPhase("cleared");
      return;
    }
    // Keep the player inside the active station.
    const cur = room.tasks[currentTaskIndex];
    if (cur && !active.taskIds.includes(cur.id)) {
      const first = active.taskIds.find(id => !completedTaskIds.has(id));
      if (first) p.goToTask(indexOf.get(first)!);
    }
  }, [phase, active, stationDone, shields, slow, currentTaskIndex, completedTaskIds, room.tasks, indexOf, updateLocal, p]);

  function enterStation(id: string) {
    const s = experience.stations.find(x => x.id === id);
    const hs = hubStations.find(x => x.id === id);
    if (!s || !hs || hs.status === "locked") return;
    if (hs.status === "cleared") p.reopenTasks(s.taskIds); // replay: best-of XP, nothing lost
    const first = hs.status === "cleared" ? s.taskIds[0] : s.taskIds.find(t => !completedTaskIds.has(t)) ?? s.taskIds[0];
    p.goToTask(indexOf.get(first)!);
    setActiveId(id);
    breachPending.current = false;
    // A replay starts clean; a station left half-way keeps the shields it had lost.
    setShields(hs.status === "cleared" ? MAX_SHIELDS : local.shields[id] || MAX_SHIELDS);
    setSlow(false);
    setTaskKey(k => k + 1);
    setPhase("station");
  }

  // Keep the count for a station in progress, so leaving it cannot refill the shields.
  useEffect(() => {
    if (phase !== "station" || !activeId || shields === MAX_SHIELDS) return;
    updateLocal(v => (v.shields[activeId] === shields ? v : { ...v, shields: { ...v.shields, [activeId]: shields } }));
  }, [phase, activeId, shields, updateLocal]);

  const markSlow = useCallback(() => setSlow(true), []);

  // A breach caused by a revealed answer is held until the learner continues,
  // so the overlay never hides the explanation they just earned.
  const breachPending = useRef(false);
  const onMistake = useCallback((withReveal?: boolean) => {
    setShields(s => {
      const next = Math.max(0, s - 1);
      if (next === 0) {
        if (withReveal) breachPending.current = true;
        else setPhase("breached");
      }
      return next;
    });
  }, []);

  function restartStation() {
    if (!active) return;
    const done = active.taskIds.filter(id => completedTaskIds.has(id));
    if (done.length) p.reopenTasks(done);
    p.goToTask(indexOf.get(active.taskIds[0])!);
    breachPending.current = false;
    updateLocal(v => {
      const { [active.id]: _breached, ...rest } = v.shields;
      void _breached;
      return { ...v, shields: rest };
    });
    setShields(MAX_SHIELDS);
    setSlow(false);
    setTaskKey(k => k + 1);
    setPhase("station");
  }

  function afterCleared() {
    // First clear of a station with a chapter film: the story moves on before the board.
    const next = active && stories.find(e => e.key === active.id);
    if (next && !local.seenStory.includes(next.key)) setStory(next);
    setActiveId(null);
    setPhase(p.showCompletion || p.showFailure ? "debrief" : "hub");
  }

  const handleComplete = useCallback((xp: number, telemetry?: TaskTelemetryEntry, passCredit?: number) => {
    const t = room.tasks[currentTaskIndex];
    if (t?.type === "reading" && !completedTaskIds.has(t.id)) updateLocal(v => ({ ...v, tokens: v.tokens + 1 }));
    p.onTaskComplete(xp, telemetry, passCredit);
    if (breachPending.current) { breachPending.current = false; setPhase("breached"); }
  }, [room.tasks, currentTaskIndex, completedTaskIds, updateLocal, p]);

  const spendToken = useCallback(() => {
    if (local.tokens <= 0) return false;
    updateLocal(v => ({ ...v, tokens: v.tokens - 1 }));
    return true;
  }, [local.tokens, updateLocal]);

  const clearedCount = hubStations.filter(s => s.status === "cleared").length;
  const task = room.tasks[currentTaskIndex];
  const taskPos = active && task ? active.taskIds.indexOf(task.id) : -1;

  // On the mission board the 3D shield sits in the board's hero slot; everywhere
  // else (and on narrow screens, where the slot is hidden) it is the backdrop.
  const [heroSlot, setHeroSlot] = useState<HTMLDivElement | null>(null);
  const [heroBox, setHeroBox] = useState<{ top: number; left: number; width: number; height: number } | null>(null);
  const measureHero = useCallback(() => {
    const r = heroSlot?.getBoundingClientRect();
    setHeroBox(r && r.width > 0 && r.height > 0 ? { top: r.top, left: r.left, width: r.width, height: r.height } : null);
  }, [heroSlot]);
  useEffect(() => {
    if (!heroSlot) { setHeroBox(null); return; }
    measureHero();
    const ro = new ResizeObserver(measureHero);
    ro.observe(heroSlot);
    window.addEventListener("resize", measureHero);
    return () => { ro.disconnect(); window.removeEventListener("resize", measureHero); };
  }, [heroSlot, measureHero]);
  const inHero = phase === "hub" && heroBox !== null;

  // Stage rooms: a full-screen world and a station picked on the track. The
  // pick follows the frontier whenever the learner comes back to the board.
  const stage = experience.layout === "stage" || experience.layout === "campus" || experience.layout === "lens";
  const World = WORLDS[experience.scene ?? "gates"] ?? WORLDS.gates;
  const frontier = Math.max(0, hubStations.findIndex(s => s.status === "open"));
  const [selected, setSelected] = useState(0);
  useEffect(() => { if (phase === "hub") setSelected(frontier); }, [phase, frontier]);

  return (
    <div className="fixed inset-0 z-40 overflow-hidden bg-[#05080f] text-slate-100">
      <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_50%_75%,rgba(34,211,238,0.10),transparent_55%),linear-gradient(rgba(148,163,184,0.04)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.04)_1px,transparent_1px)] bg-[length:100%_100%,48px_48px,48px_48px]" />
      {/* The room's 3D world (or the flat fallback). Stage rooms: full screen. */}
      {has3d && stage ? (
        <div className="pointer-events-none absolute inset-0">
          <World
            stations={hubStations}
            selected={phase === "hub" ? selected : Math.max(0, experience.stations.findIndex(s => s.id === activeId))}
            primary={experience.look?.primary ?? "#22d3ee"}
            secondary={experience.look?.secondary ?? "#a78bfa"}
            warn={experience.look?.warn ?? "#f59e0b"}
            dimmed={phase !== "hub"}
            reducedMotion={reducedMotion}
          />
        </div>
      ) : has3d ? (
        <div
          className={cn("pointer-events-none absolute", inHero ? "z-10" : "inset-0", phase === "hub" && !inHero && "invisible")}
          style={inHero ? heroBox! : undefined}
        >
          <ShieldScene
            progress={hubStations.length ? clearedCount / hubStations.length : 0}
            primary={experience.look?.primary ?? "#22d3ee"}
            secondary={experience.look?.secondary ?? "#a78bfa"}
            dimmed={phase !== "hub"}
            reducedMotion={reducedMotion}
          />
        </div>
      ) : (
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_50%_30%,rgba(34,211,238,0.12),transparent_60%)]" />
      )}

      {/* HUD */}
      <header className="pointer-events-none absolute inset-x-0 top-0 z-30 flex items-start gap-3 p-4">
        <div className="pointer-events-auto flex items-center gap-2">
          <button
            onClick={() => (phase === "station" || phase === "breached" ? (setActiveId(null), setPhase("hub")) : p.onNavigate("/rooms"))}
            aria-label={phase === "station" ? "Back to the hub" : "Back to rooms"}
            className="grid h-11 w-11 place-items-center rounded-full border border-white/15 bg-bg-panel/70 backdrop-blur hover:border-cyber-400/60"
          >
            <ArrowLeft className="h-5 w-5" />
          </button>
        </div>

        <div className={cn("mx-auto flex flex-col items-center text-center", phase === "hub" && "invisible")}>
          <div className="flex items-center gap-1.5 rounded-full border border-white/15 bg-bg-panel/70 px-4 py-2 backdrop-blur" aria-label={`${clearedCount} of ${hubStations.length} stations cleared`}>
            {hubStations.map(s => (
              <span key={s.id} className={cn(
                "h-3.5 w-3.5 rotate-45 rounded-[3px] border",
                s.status === "cleared" ? "border-neon-green bg-neon-green/80" : s.status === "open" ? "border-cyber-300 bg-cyber-400/20" : "border-slate-600 bg-transparent",
              )} />
            ))}
          </div>
          <p className="mt-2 text-[11px] font-semibold uppercase tracking-[0.3em] text-indigo-300">
            {phase === "station" && active && taskPos >= 0
              ? `${active.label} · ${taskPos + 1} of ${active.taskIds.length}`
              : experience.codename}
          </p>
        </div>

        <div className={cn("pointer-events-auto flex items-center gap-2", phase === "hub" && "invisible")}>
          <span className="inline-flex h-11 items-center gap-1.5 rounded-full border border-neon-amber/30 bg-bg-panel/70 px-3 text-sm font-bold text-neon-amber backdrop-blur" title="Intel tokens: earned in briefings, spent on hints">
            <KeyRound className="h-4 w-4" /> {local.tokens}
          </span>
          {(phase === "station" || phase === "breached") && (
            <span className="inline-flex h-11 items-center gap-1 rounded-full border border-white/15 bg-bg-panel/70 px-3 backdrop-blur" aria-label={`${shields} of ${MAX_SHIELDS} shields left`}>
              {Array.from({ length: MAX_SHIELDS }, (_, i) => (
                <motion.span key={i} animate={i >= shields ? { scale: [1.4, 1], opacity: 0.35 } : { scale: 1, opacity: 1 }}>
                  {i < shields ? <Shield className="h-5 w-5 fill-cyber-400/70 text-cyber-300" /> : <ShieldOff className="h-5 w-5 text-slate-500" />}
                </motion.span>
              ))}
            </span>
          )}
        </div>
      </header>

      <AnimatePresence mode="wait">
        {phase === "briefing" && (
          <Briefing key="briefing" experience={experience} roomTitle={room.title} reducedMotion={reducedMotion}
            onStart={() => { updateLocal(v => ({ ...v, seenBriefing: true })); setPhase("hub"); }} />
        )}

        {phase === "hub" && (
          <motion.div key="hub" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className={cn("absolute inset-0 z-20", stage && "pointer-events-none")}>
            {experience.layout === "lens" ? (
              <LensBoard
                experience={experience}
                room={room}
                stations={hubStations}
                selected={selected}
                onSelect={setSelected}
                onEnter={enterStation}
                tokens={local.tokens}
                stories={watched}
                onPlayStory={setStory}
              />
            ) : experience.layout === "campus" ? (
              <CampusBoard
                experience={experience}
                room={room}
                stations={hubStations}
                selected={selected}
                onSelect={setSelected}
                onEnter={enterStation}
                tokens={local.tokens}
                stories={watched}
                onPlayStory={setStory}
              />
            ) : stage ? (
              <StageBoard
                experience={experience}
                room={room}
                stations={hubStations}
                selected={selected}
                onSelect={setSelected}
                onEnter={enterStation}
                tokens={local.tokens}
                stories={watched}
                onPlayStory={setStory}
              />
            ) : (
            <MissionBoard
              experience={experience}
              roomTitle={room.title}
              difficulty={room.difficulty}
              stations={hubStations}
              tokens={local.tokens}
              has3d={has3d}
              onEnter={enterStation}
              onHeroSlot={setHeroSlot}
              onScroll={measureHero}
              stories={watched}
              onPlayStory={setStory}
            />
            )}
          </motion.div>
        )}

        {(phase === "station" || phase === "breached") && active && task && (
          <motion.div
            ref={panelRef}
            key={`station-${active.id}`}
            initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 24 }}
            transition={{ duration: reducedMotion ? 0 : 0.45, delay: reducedMotion ? 0 : 0.25 }}
            className="absolute inset-x-0 bottom-0 top-24 z-20 overflow-y-auto px-4 pb-10"
          >
            <div
              className="relative mx-auto max-w-5xl overflow-hidden rounded-3xl border p-5 shadow-2xl backdrop-blur-xl sm:p-7"
              style={{
                // Each room's labs wear the room's own colours, so no two rooms look alike.
                ["--room-accent" as string]: experience.look?.primary ?? "#38bdf8",
                ["--room-accent-2" as string]: experience.look?.secondary ?? "#a78bfa",
                borderColor: `${experience.look?.primary ?? "#38bdf8"}55`,
                background: `radial-gradient(120% 60% at 0% 0%, ${experience.look?.primary ?? "#38bdf8"}1f, transparent 60%), radial-gradient(90% 50% at 100% 100%, ${experience.look?.secondary ?? "#a78bfa"}1a, transparent 60%), #070c17d9`,
              }}
            >
              <div aria-hidden className="absolute inset-x-0 top-0 h-1" style={{ background: `linear-gradient(90deg, ${experience.look?.primary ?? "#38bdf8"}, ${experience.look?.secondary ?? "#a78bfa"})` }} />
              <StationTask
                key={`${task.id}:${taskKey}`}
                task={task}
                labs={experience.briefings?.[task.id]}
                props={{
                  roomId: room.id, isCompleted: completedTaskIds.has(task.id),
                  onComplete: handleComplete, onMistake, onSlow: markSlow, persona: experience.personas?.[task.id],
                  prevLogEvent: p.prevLogEvent, intelTokens: local.tokens, spendToken,
                }}
              />
            </div>
          </motion.div>
        )}

        {phase === "cleared" && active && (
          <Overlay key="cleared" tone="green">
            <p className="text-[11px] font-semibold uppercase tracking-[0.3em] text-neon-green">Station cleared</p>
            <h2 className="mt-2 text-3xl font-extrabold text-white">{active.label}</h2>
            <Stars n={lastStars} big className="mt-4 justify-center" />
            <p className="mt-3 text-sm text-slate-300">
              {lastStars === 3
                ? "Clean work. Not a single shield lost."
                : [
                    MAX_SHIELDS - shields > 0 ? `${MAX_SHIELDS - shields} shield${MAX_SHIELDS - shields === 1 ? "" : "s"} lost.` : "",
                    slow ? "One star for running over time." : "",
                    "Replay any time for 3 stars.",
                  ].filter(Boolean).join(" ")}
            </p>
            <button autoFocus onClick={afterCleared} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-6 py-3 text-sm font-bold text-bg">
              {p.showCompletion || p.showFailure ? "Debrief" : "Back to the floor"} <ChevronRight className="h-4 w-4" />
            </button>
          </Overlay>
        )}

        {phase === "breached" && active && (
          <Overlay key="breached" tone="red">
            <ShieldOff className="mx-auto h-12 w-12 text-neon-red" />
            <h2 className="mt-3 text-3xl font-extrabold text-neon-red">Station breached</h2>
            <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-slate-300">
              All three shields are gone. Go back over the evidence and run {active.label} again from the start.
              The XP you already earned stays.
            </p>
            <button autoFocus onClick={restartStation} className="mt-6 inline-flex items-center gap-2 rounded-xl bg-neon-red/90 px-6 py-3 text-sm font-bold text-white hover:bg-neon-red">
              <RotateCcw className="h-4 w-4" /> Restart station
            </button>
          </Overlay>
        )}

        {phase === "debrief" && (
          <Debrief key="debrief" {...p} hubStations={hubStations} onHub={() => setPhase("hub")} />
        )}
      </AnimatePresence>

      {/* Story films sit above every phase; closing one reveals whatever is underneath. */}
      <AnimatePresence>
        {story && <StoryPlayer key={story.key} clip={story.clip} label={story.label} onDone={closeStory} />}
      </AnimatePresence>
    </div>
  );
}

// ─── Station task: mechanic by task type, existing player as the fallback ───────
export function StationTask({ task, props, labs }: { task: SanitizedRoomTask; props: Omit<MechanicProps<unknown>, "task">; labs?: BriefingLab[] }) {
  if (task.type === "reading" && labs?.length) return <IntelBriefing {...props} task={task} labs={labs} />;
  if (labs?.length) return <Drill labs={labs} skip={props.isCompleted}><StationTask task={task} props={props} /></Drill>;
  switch (mechanicFor(task.type)) {
    case "lock_terminal":  return <LockTerminal  {...props} task={task as Extract<SanitizedRoomTask, { type: "question" }>} />;
    case "triage_desk":    return <TriageDesk    {...props} task={task as Extract<SanitizedRoomTask, { type: "analyst_choice" }>} />;
    case "evidence_board": return <EvidenceBoard {...props} task={task as Extract<SanitizedRoomTask, { type: "log_analysis" }>} />;
    case "vault_keypad":   return <VaultKeypad   {...props} task={task as Extract<SanitizedRoomTask, { type: "flag" }>} />;
    default:
      // intel_briefing + classic: the proven player (reading dwell gate, checkpoint,
      // matching/ordering boards) inside the station frame.
      return (
        <div className="space-y-3">
          {task.type === "reading" && (
            <p className="inline-flex items-center gap-2 rounded-full border border-neon-amber/30 bg-neon-amber/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] text-neon-amber">
              <KeyRound className="h-3.5 w-3.5" /> Intel briefing · +1 Intel token
            </p>
          )}
          <TaskPlayer roomId={props.roomId} task={task} onComplete={props.onComplete} isCompleted={props.isCompleted} prevLogEvent={props.prevLogEvent} />
        </div>
      );
  }
}

function Stars({ n, big, className }: { n: number; big?: boolean; className?: string }) {
  return (
    <span className={cn("flex gap-0.5", className)} aria-label={`${n} of 3 stars`}>
      {[0, 1, 2].map(i => (
        <Star key={i} className={cn(big ? "h-8 w-8" : "h-3.5 w-3.5", i < n ? "fill-neon-amber text-neon-amber" : "text-slate-600")} />
      ))}
    </span>
  );
}

function Overlay({ children, tone }: { children: React.ReactNode; tone: "green" | "red" }) {
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="absolute inset-0 z-40 grid place-items-center bg-black/55 px-4 backdrop-blur-sm">
      <motion.div
        role="dialog" aria-modal="true"
        initial={{ scale: 0.92, y: 12 }} animate={{ scale: 1, y: 0 }}
        className={cn(
          "w-full max-w-md rounded-3xl border p-8 text-center shadow-2xl",
          tone === "green" ? "border-neon-green/40 bg-[#06140f]/90" : "border-neon-red/40 bg-[#1a0710]/90",
        )}
      >
        {children}
      </motion.div>
    </motion.div>
  );
}

// ─── Briefing: the handler types the situation out ─────────────────────────────
function Briefing({ experience, roomTitle, reducedMotion, onStart }: { experience: RoomExperience; roomTitle: string; reducedMotion: boolean; onStart: () => void }) {
  const full = experience.briefing.join("\n");
  const [n, setN] = useState(reducedMotion ? full.length : 0);
  useEffect(() => {
    if (n >= full.length) return;
    const t = setTimeout(() => setN(x => x + 1), full[n] === "\n" ? 380 : 28);
    return () => clearTimeout(t);
  }, [n, full]);
  const done = n >= full.length;
  return (
    <motion.div key="briefing" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="absolute inset-0 z-30 grid place-items-center bg-black/60 px-6">
      <div className="w-full max-w-3xl">
        <p className="text-[11px] font-semibold uppercase tracking-[0.35em] text-indigo-300">{experience.codename} · {roomTitle}</p>
        {/* The untyped remainder is rendered invisibly so the layout never shifts
            under the Start button while the text types out. */}
        <pre aria-label={full} className="mt-6 whitespace-pre-wrap font-mono text-xl leading-relaxed text-slate-100 sm:text-2xl">
          <span aria-hidden>{full.slice(0, n)}</span>
          {!done && <span aria-hidden className="ml-0.5 inline-block h-6 w-3 animate-pulse bg-cyber-300 align-middle" />}
          <span aria-hidden className="opacity-0">{full.slice(n)}</span>
        </pre>
        <p className="mt-4 text-sm text-slate-400">— {experience.handler.name}, {experience.handler.role}</p>
        <div className="mt-8 flex gap-3">
          <button autoFocus onClick={onStart} className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-6 py-3 text-sm font-bold text-bg hover:brightness-110">
            Start operation <ChevronRight className="h-4 w-4" />
          </button>
          {!done && (
            <button onClick={() => setN(full.length)} className="rounded-xl border border-white/20 px-5 py-3 text-sm text-slate-300 hover:border-white/40">Skip</button>
          )}
        </div>
      </div>
    </motion.div>
  );
}

// ─── Debrief: the room's real result (same score / pass gate as Classic) ────────
function Debrief(p: OperationViewProps & { hubStations: HubStation[]; onHub: () => void }) {
  const passed = p.showCompletion;
  return (
    <Overlay tone={passed ? "green" : "red"}>
      {passed && <RoomCelebration roomId={p.room.id} />}
      {passed ? (
        <motion.div initial={{ scale: 0.4, rotate: -14 }} animate={{ scale: 1, rotate: 0 }} transition={{ type: "spring", stiffness: 240, damping: 11 }}>
          <Trophy className="mx-auto h-14 w-14 text-neon-amber drop-shadow-[0_0_18px_rgba(251,191,36,0.55)]" />
        </motion.div>
      ) : <RotateCcw className="mx-auto h-11 w-11 text-neon-amber" />}
      <p className="mt-3 text-[11px] font-semibold uppercase tracking-[0.3em] text-slate-400">{p.experience.codename}</p>
      <h2 className={cn("mt-1 text-3xl font-extrabold", passed ? "text-white" : "text-neon-amber")}>{passed ? "Operation complete" : "Almost there"}</h2>
      {passed && (
        <div className="mt-2">
          <p className="text-sm font-bold text-neon-green">{roomRank(p.scorePct).title}</p>
          <p className="text-xs text-slate-300">{roomRank(p.scorePct).line}</p>
        </div>
      )}
      <div className="mt-5 grid grid-cols-2 gap-3 text-left">
        <div className="rounded-xl border border-white/10 bg-black/30 p-3">
          <p className="text-[11px] uppercase tracking-wider text-slate-400">Score</p>
          <p className={cn("font-mono text-2xl font-bold", passed ? "text-neon-green" : "text-neon-amber")}>{p.scorePct}%</p>
          <p className="text-[10px] text-slate-500">{p.passPct}% to pass</p>
        </div>
        <div className="rounded-xl border border-white/10 bg-black/30 p-3">
          <p className="text-[11px] uppercase tracking-wider text-slate-400">XP earned</p>
          <p className="font-mono text-2xl font-bold text-neon-amber">{passed ? <CountUp to={p.totalXpEarned} prefix="+" /> : `+${p.totalXpEarned}`}</p>
        </div>
      </div>
      <ul className="mt-4 space-y-1.5 text-left text-sm">
        {p.hubStations.map(s => (
          <li key={s.id} className="flex items-center justify-between rounded-lg bg-white/5 px-3 py-1.5">
            <span className="text-slate-200">{s.label}</span>
            {s.status === "cleared" ? <Stars n={s.stars} /> : <span className="text-xs text-slate-500">not cleared</span>}
          </li>
        ))}
      </ul>
      {!passed && (
        <p className="mt-4 text-sm text-slate-300">
          {p.missedCount === 1 ? "One task" : `${p.missedCount} tasks`} to revisit. Your correct answers stay done.
        </p>
      )}
      <div className="mt-6 flex flex-col gap-2">
        {passed ? (
          <>
            {p.nextRoom && (
              <button onClick={() => p.onNavigate(`/rooms/${p.nextRoom!.id}`)} className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-cyber-400 to-indigo-400 px-5 py-3 text-sm font-bold text-bg">
                {p.nextRoom.started ? "Continue" : "Next"}: {p.nextRoom.title} <ChevronRight className="h-4 w-4" />
              </button>
            )}
            <button onClick={p.onHub} className="rounded-xl border border-white/15 px-5 py-2.5 text-sm text-slate-200 hover:border-cyber-400/50">Back to the floor (replay for stars)</button>
            <button onClick={p.onStartReview} className="inline-flex items-center justify-center gap-2 rounded-xl border border-white/15 px-5 py-2.5 text-sm text-slate-200 hover:border-cyber-400/50">
              <Eye className="h-4 w-4" /> Review room
            </button>
          </>
        ) : (
          <button onClick={p.onReviewMissed} className="inline-flex items-center justify-center gap-2 rounded-xl bg-neon-amber px-5 py-3 text-sm font-bold text-bg">
            <RotateCcw className="h-4 w-4" /> Revisit {p.missedCount === 1 ? "1 task" : `${p.missedCount} tasks`}
          </button>
        )}
        <button onClick={() => p.onNavigate("/rooms")} className="rounded-xl px-5 py-2 text-sm text-slate-400 hover:text-white">Back to Rooms</button>
      </div>
    </Overlay>
  );
}
