import "server-only";
/**
 * Server-side deterministic timeline for a team session (Phase 0.4). Builds the
 * SAME real telemetry the single-player dashboard uses — the company's benign
 * event pool interleaved with a fitting attack story — into a flat, time-ordered
 * list the start route writes to session_injects. pg_cron then promotes each
 * entry into session_events on time, and Broadcast-from-DB fans it to the team.
 *
 * Deterministic: a given (companyId, difficulty, seed) always yields the same
 * feed, so every member replays an identical incident and an AAR can reconstruct
 * it exactly.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { BENIGN_EVENTS } from "@/app/(app)/dashboard/benignEvents";
import { COMPANY_EVENTS } from "@/lib/sim/companyProfiles";
import { pickStoryForCompany, instantiateStory } from "@/app/(app)/dashboard/attackStories";
import { COMPANY_PROFILES } from "@/lib/sim/companyProfilesMeta";

// channel "feed" → promoted as a feed.event (a log); "inject" → a staff.inject
// (an MSEL curveball: management pressure, a help-desk ticket, an announcement).
export interface TimelineEntry { due_offset_ms: number; channel: "feed" | "inject"; body: Record<string, unknown> }

function hashSeed(s: string): number {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function mulberry32(a: number) {
  return () => {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function sampleN<T>(arr: T[], n: number, rnd: () => number): T[] {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; }
  return a.slice(0, Math.min(n, a.length));
}

/** Build the ordered, time-stamped feed for a session. */
export function buildTeamTimeline(companyId: string, difficulty: "easy" | "medium" | "hard", seed: string): TimelineEntry[] {
  const rnd = mulberry32(hashSeed(`${companyId}:${difficulty}:${seed}`));
  const companyPool = (COMPANY_EVENTS[companyId]?.length ? COMPANY_EVENTS[companyId] : BENIGN_EVENTS) ?? [];
  const edr = COMPANY_PROFILES.find(c => c.id === companyId)?.architecture.edr;

  const buildStory = (): TelemetryEvent[] => {
    try {
      const story = pickStoryForCompany(companyId, difficulty);
      return instantiateStory(story, companyPool, edr, companyId).events ?? [];
    } catch { return []; }
  };
  const attack1 = buildStory();
  // Second concurrent incident: a distinct story so several Tier-1/Tier-2 analysts
  // have parallel work and the Manager must prioritise between two live cases
  // (removes the "one incident drains to the whole team" dead time). pickStoryForCompany
  // dedups against recent picks, so this is (almost always) a different story.
  // Skipped on easy to keep a beginner shift single-threaded.
  const attack2 = difficulty === "easy" ? [] : buildStory();

  // Benign noise: the company's own pool FIRST (tenant flavour), topped up from the
  // large generic pool, de-duped by id, attack-verdict events excluded. Combining
  // them removes the old per-company cap (some tenant pools held only ~34 events, so
  // the feed ran dry early) and gives every company deep, continuous noise.
  const seenBenign = new Set<string>();
  const benignPool = [...companyPool, ...BENIGN_EVENTS]
    .filter(e => e.expected_verdict !== "tp" && e.expected_verdict !== "escalate")
    .filter(e => { const k = String(e.id ?? ""); if (!k || seenBenign.has(k)) return k ? false : true; seenBenign.add(k); return true; });
  // Enough continuous benign noise to sustain a realistic ~20–26 min shift (the
  // attacks hide inside it), not a ~7 min burst that then goes silent.
  const benignN = difficulty === "hard" ? 120 : difficulty === "easy" ? 55 : 90;
  const benign = sampleN(benignPool, benignN, rnd);

  const total = benign.length + attack1.length + attack2.length;
  if (total === 0) return [];

  // Place each incident in its own position window so they overlap in time: the
  // primary across the back 30–100% of the shift, the second incident earlier
  // (12–58%). One shared position map keeps every attack slot unique.
  const posToAttack = new Map<number, TelemetryEvent>();
  const place = (evs: TelemetryEvent[], startFrac: number, endFrac: number) => {
    if (evs.length === 0) return;
    const start = Math.floor(total * startFrac);
    const end = Math.min(total - 1, Math.floor(total * endFrac));
    const denom = Math.max(1, evs.length - 1);
    for (let i = 0; i < evs.length; i++) {
      let pos = Math.min(end, start + Math.round((i * (end - start)) / denom));
      while (posToAttack.has(pos) && pos < total - 1) pos++;
      while (posToAttack.has(pos) && pos > 0) pos--;
      posToAttack.set(pos, evs[i]);
    }
  };
  // Cluster each incident into its own ~10-min window (a band of positions) so it
  // reads as an unfolding attack, not one event every few minutes lost in a long shift.
  place(attack1, 0.42, 0.82);
  place(attack2, 0.12, 0.52);

  const ordered: { ev: TelemetryEvent; isAttack: boolean }[] = [];
  let bi = 0;
  for (let pos = 0; pos < total; pos++) {
    const atk = posToAttack.get(pos);
    if (atk) ordered.push({ ev: atk, isAttack: true });
    else if (bi < benign.length) ordered.push({ ev: benign[bi++], isAttack: false });
  }

  // Cadence: an event every ~11–18s (+ up to 3.5s jitter), denser on hard. Sized so
  // the benign counts above sustain a full ~20–26 min shift instead of ~7 min.
  const baseGap = difficulty === "hard" ? 9000 : difficulty === "easy" ? 14000 : 12000;
  let t = 2000;
  const feed: TimelineEntry[] = ordered.map(({ ev, isAttack }, i) => {
    // Ground truth for the team report: every event that belongs to the attack
    // story is the attack (carry a tp/escalate verdict even if the source pool
    // left it null); benign noise keeps its own verdict.
    const verdict = isAttack
      ? (ev.expected_verdict === "fp" ? "escalate" : (ev.expected_verdict ?? "tp"))
      : ev.expected_verdict;
    const entry: TimelineEntry = {
      due_offset_ms: t,
      channel: "feed",
      // stamp a stable per-feed id so duplicate pool ids can't collide in the room
      body: { ...ev, id: `${ev.id ?? "ev"}__${i}`, expected_verdict: verdict },
    };
    t += baseGap + Math.floor(rnd() * 3500);
    return entry;
  });

  // MSEL — a few scripted injects timed against the shift so tempo and curveballs
  // don't depend on a live facilitator constantly typing. Placed as fractions of
  // the feed's span. Skipped on easy (a beginner shift stays uncluttered).
  const span = feed.length ? feed[feed.length - 1].due_offset_ms : 0;
  // A5: three management-pressure beats (not one) so the pressure→SITREP loop and its
  // rubric have real signal even with NO instructor in the room — the SOC Manager still
  // gets exercised on cadence under escalating pressure.
  const msel: TimelineEntry[] = (difficulty === "easy" || span === 0) ? [] : [
    { due_offset_ms: Math.floor(span * 0.30), channel: "inject", body: { kind: "mgmt_pressure", text: "CISO wants a status update on the suspicious activity within 15 minutes — is this contained, or spreading?" } },
    { due_offset_ms: Math.floor(span * 0.55), channel: "inject", body: { kind: "ticket", text: "A user in Finance says someone from 'IT support' phoned asking them to read back an MFA code to 'verify their account'. How should this be handled?" } },
    { due_offset_ms: Math.floor(span * 0.62), channel: "inject", body: { kind: "mgmt_pressure", text: "Legal is asking whether this is a reportable/notifiable incident — they need your read on scope and data exposure." } },
    { due_offset_ms: Math.floor(span * 0.78), channel: "inject", body: { kind: "announcement", text: "Reminder: log every containment decision with its rationale — this incident will be reviewed after the shift." } },
    { due_offset_ms: Math.floor(span * 0.90), channel: "inject", body: { kind: "mgmt_pressure", text: "Exec team wants a one-line bottom line for the leadership channel: what happened, what's the impact, what are we doing about it?" } },
  ];

  return [...feed, ...msel].sort((a, b) => a.due_offset_ms - b.due_offset_ms);
}
