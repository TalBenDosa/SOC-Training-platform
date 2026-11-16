/**
 * Turns a recommended-track step (kind + id) into what the page shows: title, link,
 * minutes, slide deck, video, and the platform feature it belongs to.
 *
 * Client-safe: reads only the generated, answer-free indexes (roomsMeta,
 * libraryIndex, catalogMeta), the lesson catalogue and the light company meta.
 */
import { ROOMS_META } from "@/data/roomsMeta";
import { LIBRARY_INDEX } from "@/data/libraryIndex";
import { QUIZZES_META, SCENARIOS_META } from "@/data/catalogMeta";
import { LESSON_SLIDES } from "@/data/lessonSlides";
import { LESSON_VIDEOS } from "@/data/lessonVideos";
import { LESSON_PATHS } from "@/lib/lessons/paths";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";
import type { FeatureKey } from "@/lib/brand/features";
import type { TrackStep, TrackStepKind } from "@/data/recommendedTracks";

/** The live-dashboard companies in unlock order (mirrors dashboard/page.tsx COMPANY_ORDER). */
export const SHIFT_COMPANY_ORDER = ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank"] as const;

export interface ResolvedStep extends TrackStep {
  key: string;
  title: string;
  href: string;
  minutes: number;
  feature: FeatureKey;
  /** Library lessons: the slide deck shown in the in-app viewer. */
  deck?: { src: string; pages: number };
  /** Library lessons: an explainer video plays inside the lesson. */
  hasVideo?: boolean;
  /** Short secondary line (category, difficulty, company industry...). */
  detail?: string;
}

export const KIND_LABEL: Record<TrackStepKind, string> = {
  read: "Lesson",
  lesson: "Graded lesson",
  room: "Room",
  quiz: "Quiz",
  scenario: "Scenario",
  shift: "Live shift",
};

const FEATURE_OF: Record<TrackStepKind, FeatureKey> = {
  read: "learning_path",
  lesson: "learning_path",
  room: "learning_rooms",
  quiz: "quizzes",
  scenario: "scenarios",
  shift: "live_soc",
};

/** Fallback minutes where the index has none. */
const DEFAULT_MINUTES: Record<TrackStepKind, number> = {
  read: 60, lesson: 12, room: 50, quiz: 15, scenario: 30, shift: 30,
};

const cap = (s: string) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

const ROOM_BY_ID = new Map(ROOMS_META.map(r => [r.id, r]));
const LIB_BY_ID = new Map(LIBRARY_INDEX.map(l => [l.id, l]));
const QUIZ_BY_SLUG = new Map(QUIZZES_META.map(q => [q.slug, q]));
const SCEN_BY_SLUG = new Map(SCENARIOS_META.map(s => [s.slug, s]));
const COMPANY_BY_ID = new Map(COMPANY_PROFILES.map(c => [c.id, c]));
const PATH_LESSON_BY_KEY = new Map<string, { path: (typeof LESSON_PATHS)[number]; module: (typeof LESSON_PATHS)[number]["modules"][number]; lesson: (typeof LESSON_PATHS)[number]["modules"][number]["lessons"][number] }>(
  LESSON_PATHS.flatMap(p => p.modules.flatMap(m => m.lessons.map(l => [`${p.slug}--${l.slug}`, { path: p, module: m, lesson: l }] as const))),
);

export const stepKey = (s: TrackStep) => `${s.kind}:${s.id}`;

/** Null when the id does not exist (the content test fails on that). */
export function resolveStep(step: TrackStep): ResolvedStep | null {
  const base = { ...step, key: stepKey(step), feature: FEATURE_OF[step.kind] };
  switch (step.kind) {
    case "room": {
      const r = ROOM_BY_ID.get(step.id);
      if (!r) return null;
      return { ...base, title: r.title, href: `/rooms/${r.id}`, minutes: r.estimatedMinutes || DEFAULT_MINUTES.room, detail: `${r.category} · ${cap(r.difficulty)}` };
    }
    case "read": {
      const l = LIB_BY_ID.get(step.id);
      if (!l) return null;
      const slides = LESSON_SLIDES[l.slug];
      return {
        ...base,
        title: l.title,
        href: `/learn?open=${encodeURIComponent(l.id)}`,
        minutes: l.estimatedMinutes || DEFAULT_MINUTES.read,
        deck: slides ? { src: slides.src, pages: slides.pages } : undefined,
        hasVideo: !!LESSON_VIDEOS[l.slug],
        detail: l.topic,
      };
    }
    case "lesson": {
      const hit = PATH_LESSON_BY_KEY.get(step.id);
      if (!hit) return null;
      return {
        ...base,
        title: hit.lesson.title,
        href: `/learn/${hit.path.slug}/${hit.lesson.slug}`,
        minutes: hit.lesson.min || DEFAULT_MINUTES.lesson,
        detail: `${hit.path.title} · ${hit.module.title}`,
      };
    }
    case "quiz": {
      const q = QUIZ_BY_SLUG.get(step.id);
      if (!q) return null;
      return { ...base, title: q.title, href: `/quizzes/${q.slug}`, minutes: DEFAULT_MINUTES.quiz, detail: `${q.category} · ${cap(q.difficulty)}` };
    }
    case "scenario": {
      const s = SCEN_BY_SLUG.get(step.id);
      if (!s) return null;
      return { ...base, title: s.title, href: `/scenarios/${s.slug}`, minutes: DEFAULT_MINUTES.scenario, detail: cap(s.difficulty) };
    }
    case "shift": {
      const c = COMPANY_BY_ID.get(step.id);
      if (!c || !(SHIFT_COMPANY_ORDER as readonly string[]).includes(c.id)) return null;
      return { ...base, title: `Secure ${c.name}`, href: "/dashboard", minutes: DEFAULT_MINUTES.shift, detail: `${c.industry} · live SOC Dashboard` };
    }
  }
}

/** Resolved steps, dropping unknown ids and steps whose feature this environment does not have. */
export function resolveSteps(steps: readonly TrackStep[] | undefined, hasFeature: (f: FeatureKey) => boolean = () => true): ResolvedStep[] {
  return (steps ?? []).map(resolveStep).filter((s): s is ResolvedStep => !!s && hasFeature(s.feature));
}
