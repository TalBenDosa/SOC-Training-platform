/**
 * The card-sized record of a Lesson Library lesson: everything the /learn
 * grid and the admin syllabus list show without opening the lesson. Shared by
 * the index generator (scripts/generate-library-index.mjs), the content gate's
 * staleness check and the tests, so all three derive it the same way.
 */
export interface LibraryEntry {
  id: string;
  slug: string;
  title: string;
  topic: string;
  difficulty: string;
  xp?: number;
  estimatedMinutes?: number;
  /** Number of content sections (the reader adds an intro page on top). */
  sectionCount: number;
  /** First line of the intro, markdown bold removed: the card's description. */
  blurb: string;
  researchUsed?: boolean;
  published_at?: string;
}

interface LessonLike {
  id: string;
  slug: string;
  title: string;
  topic: string;
  difficulty: string;
  xp?: number;
  estimatedMinutes?: number;
  intro?: string;
  sections?: unknown[];
  researchUsed?: boolean;
  published_at?: string;
}

// The card clamps the blurb to four lines, so anything past this never shows.
const BLURB_MAX = 280;

/** Cut at a word boundary; the card's line clamp draws the ellipsis. */
function clip(s: string, max: number): string {
  if (s.length <= max) return s;
  const cut = s.slice(0, max);
  const sp = cut.lastIndexOf(" ");
  return sp > max * 0.6 ? cut.slice(0, sp) : cut;
}

export function libraryEntry(l: LessonLike): LibraryEntry {
  const e: LibraryEntry = {
    id: l.id,
    slug: l.slug,
    title: l.title,
    topic: l.topic,
    difficulty: l.difficulty,
    xp: l.xp,
    estimatedMinutes: l.estimatedMinutes,
    sectionCount: l.sections?.length ?? 0,
    blurb: clip((l.intro ?? "").replace(/\*\*/g, "").split("\n")[0], BLURB_MAX),
  };
  if (l.researchUsed) e.researchUsed = true;
  if (l.published_at) e.published_at = l.published_at;
  return e;
}
