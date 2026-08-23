import "server-only";
import { randomUUID } from "crypto";
import type { ScenarioBundle, ScenarioQuestion, TelemetryEvent, IOC, LogSource, EventType } from "@/lib/sim/types";
import { eventsToAlerts } from "@/lib/sim/scenarios";
import { LOG_SOURCES, EVENT_TYPES, IOC_TYPES } from "@/lib/scenarios/authoredConstants";

/**
 * Authored-scenario split/recombine (Phase 2 — migrations 0040 + 0041).
 *
 * A manually-authored scenario is stored as TWO projections:
 *   - CLIENT-SAFE (content_scenarios.content): briefing, the events to
 *     investigate, derived alerts, and questions WITHOUT their answers. This is
 *     RLS-readable by org members and is what the /scenarios listing + play page
 *     see.
 *   - ANSWER KEY (content_scenario_keys.answer_key): the true verdict
 *     (attack_kind), threat actor, narrative, objectives, kill-chain, the IOC
 *     truth list, and each question's answer + explanation. Lives in a table the
 *     browser physically cannot read (0041). Only the resolver + grade route
 *     (service role) recombine the two into a full ScenarioBundle in server
 *     memory.
 *
 * `splitAuthored` is the ONLY producer of both projections, so it is where every
 * field is allowlist-rebuilt and every id is namespaced.
 */

export interface AuthoredScenarioInput {
  id?: string;
  title?: unknown;
  difficulty?: unknown;
  isBenign?: unknown;
  attackKindLabel?: unknown;
  threatActor?: unknown;
  briefing?: unknown;
  narrative?: unknown;
  learningObjectives?: unknown;
  baseTime?: unknown;
  events?: unknown;
  iocs?: unknown;
  questions?: unknown;
}

export type SplitResult =
  | { ok: true; id: string; safeContent: Record<string, unknown>; answerKey: Record<string, unknown> }
  | { ok: false; error: string };

const str = (v: unknown, max: number) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const strArr = (v: unknown, max: number, cap = 20) =>
  Array.isArray(v) ? v.map(x => str(x, max)).filter(Boolean).slice(0, cap) : [];
const num = (v: unknown, def: number, min: number, maxV: number) => {
  const n = typeof v === "number" ? v : Number(v);
  return Number.isFinite(n) ? Math.min(maxV, Math.max(min, Math.round(n))) : def;
};

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "scenario";
}
function newId(orgId: string, title: string): string {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return `org-${ns}-${slugify(title)}-${randomUUID().slice(0, 4)}`;
}
export function isOrgScenarioIdFor(id: string, orgId: string): boolean {
  const ns = orgId.replace(/-/g, "").slice(0, 8);
  return typeof id === "string" && id.startsWith(`org-${ns}-`);
}

/** "key: value" lines → object. Non-fatal: bad lines are skipped. */
function parseRaw(text: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (typeof text !== "string") return out;
  for (const line of text.split("\n").slice(0, 60)) {
    const i = line.indexOf(":");
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().slice(0, 80);
    const v = line.slice(i + 1).trim().slice(0, 400);
    if (k) out[k] = v;
  }
  return out;
}

export function splitAuthored(orgId: string, input: AuthoredScenarioInput): SplitResult {
  const title = str(input.title, 160);
  if (!title) return { ok: false, error: "Give the scenario a title." };
  const briefing = str(input.briefing, 3000);
  if (!briefing) return { ok: false, error: "Write the briefing — the ticket text your analyst first sees." };
  const narrative = str(input.narrative, 6000);
  if (!narrative) return { ok: false, error: "Write the debrief narrative (revealed after a full attempt)." };

  const id = input.id && isOrgScenarioIdFor(str(input.id, 120), orgId) ? str(input.id, 120) : newId(orgId, title);
  const base = (() => {
    const t = typeof input.baseTime === "string" ? new Date(input.baseTime) : new Date();
    return Number.isNaN(t.getTime()) ? new Date() : t;
  })();

  // ── events (evidence — client-visible) ──────────────────────────────────────
  const rawEvents = Array.isArray(input.events) ? input.events : [];
  const events: TelemetryEvent[] = rawEvents
    .map((e, i) => {
      const o = (e ?? {}) as Record<string, unknown>;
      const description = str(o.description, 1000);
      if (!description) return null;
      const source = (LOG_SOURCES.includes(str(o.source, 40) as LogSource) ? str(o.source, 40) : "siem") as LogSource;
      const event_type = (EVENT_TYPES.includes(str(o.eventType, 40) as EventType) ? str(o.eventType, 40) : "edr_alert") as EventType;
      const ts = new Date(base.getTime() + num(o.offsetMin, i, 0, 100000) * 60000).toISOString();
      return { id: `${id}-e${i + 1}`, ts, source, event_type, description, raw: parseRaw(o.rawText) } as TelemetryEvent;
    })
    .filter((e): e is TelemetryEvent => e !== null)
    .slice(0, 40);
  if (events.length === 0) return { ok: false, error: "Add at least one telemetry event for the analyst to investigate." };

  // ── questions (split: options client-safe, answers server-only) ─────────────
  const rawQs = Array.isArray(input.questions) ? input.questions : [];
  const safeQuestions: { id: string; prompt: string; kind: "single" | "multi"; options: { value: string; label: string }[]; xp: number }[] = [];
  const keyQuestions: { id: string; answer: string | string[]; explanation: string; xp: number }[] = [];
  rawQs.forEach((q, qi) => {
    const o = (q ?? {}) as Record<string, unknown>;
    const prompt = str(o.prompt, 600);
    const kind: "single" | "multi" = o.kind === "multi" ? "multi" : "single";
    const options = (Array.isArray(o.options) ? o.options : [])
      .map((label, idx) => ({ value: `o${idx + 1}`, label: str(label, 400) }))
      .filter(op => op.label);
    if (!prompt || options.length < 2) return;
    const validValues = new Set(options.map(op => op.value));
    const correctIdx = Array.isArray(o.correct) ? o.correct : [];
    const correctValues = correctIdx.map(i => `o${Number(i) + 1}`).filter(v => validValues.has(v));
    if (correctValues.length === 0) return; // no correct answer marked — skip
    const qid = `${id}-q${qi + 1}`;
    const xp = num(o.xp, 50, 0, 200);
    safeQuestions.push({ id: qid, prompt, kind, options, xp });
    keyQuestions.push({
      id: qid,
      answer: kind === "multi" ? correctValues : correctValues[0],
      explanation: str(o.explanation, 1500),
      xp,
    });
  });
  if (safeQuestions.length === 0) {
    return { ok: false, error: "Add at least one question with two or more options and a marked correct answer." };
  }

  // ── iocs (answer key — grading truth) ───────────────────────────────────────
  const iocs: IOC[] = (Array.isArray(input.iocs) ? input.iocs : [])
    .map((x): IOC | null => {
      const o = (x ?? {}) as Record<string, unknown>;
      const type = str(o.type, 20);
      const value = str(o.value, 300);
      if (!IOC_TYPES.includes(type as IOC["type"]) || !value) return null;
      return { type: type as IOC["type"], value, reputation: "malicious" };
    })
    .filter((x): x is IOC => x !== null)
    .slice(0, 30);

  const attack_kind = input.isBenign === true || input.isBenign === "true"
    ? "false_positive"
    : (slugify(str(input.attackKindLabel, 60) || "intrusion"));

  // Derive alerts from events; if none qualify (authored events rarely carry
  // mitre+severity), synthesize one from the briefing so the queue isn't empty.
  let alerts = eventsToAlerts(events, id);
  if (alerts.length === 0) {
    const first = events[0];
    alerts = [{
      id: `alt_${id.slice(0, 10)}_1`,
      alert_uid: "ORG-00000001",
      title,
      description: briefing.slice(0, 240),
      source: first.source,
      vendor: (first.vendor ?? first.source).toUpperCase(),
      severity: "medium",
      status: "new",
      confidence: 70,
      risk_score: 60,
      detected_at: first.ts,
      related_events: events.map(e => e.id).slice(0, 20),
    }];
  }

  const safeContent = {
    kind: "authored",
    scenario_id: id,
    title,
    difficulty: str(input.difficulty, 20) || "intermediate",
    briefing,
    alerts,
    events,
    questions: safeQuestions,
  };
  const answerKey = {
    attack_kind,
    threat_actor: str(input.threatActor, 160),
    narrative,
    learning_objectives: strArr(input.learningObjectives, 300),
    killchain: [] as { ts: string; phase: string; action: string }[],
    iocs,
    questions: keyQuestions,
  };

  return { ok: true, id, safeContent, answerKey };
}

/** Recombine the two stored projections into a full gradable ScenarioBundle. */
export function recombineScenario(safeContent: Record<string, unknown>, answerKey: Record<string, unknown>): ScenarioBundle {
  const id = String(safeContent.scenario_id ?? "");
  const events = (Array.isArray(safeContent.events) ? safeContent.events : []) as TelemetryEvent[];
  const safeQs = (Array.isArray(safeContent.questions) ? safeContent.questions : []) as {
    id: string; prompt: string; kind: "single" | "multi"; options: { value: string; label: string }[]; xp: number;
  }[];
  const keyQs = (Array.isArray(answerKey.questions) ? answerKey.questions : []) as {
    id: string; answer: string | string[]; explanation: string; xp: number;
  }[];
  const keyById = new Map(keyQs.map(q => [q.id, q]));

  const questions: ScenarioQuestion[] = safeQs.map(q => {
    const k = keyById.get(q.id);
    return {
      id: q.id,
      prompt: q.prompt,
      kind: q.kind,
      options: q.options,
      xp: q.xp,
      answer: k?.answer ?? (q.kind === "multi" ? [] : ""),
      explanation: k?.explanation ?? "",
    };
  });

  return {
    scenario_id: id,
    title: String(safeContent.title ?? ""),
    threat_actor: String(answerKey.threat_actor ?? ""),
    attack_kind: String(answerKey.attack_kind ?? "intrusion"),
    briefing: String(safeContent.briefing ?? ""),
    narrative: String(answerKey.narrative ?? ""),
    learning_objectives: Array.isArray(answerKey.learning_objectives) ? answerKey.learning_objectives as string[] : [],
    alerts: (Array.isArray(safeContent.alerts) ? safeContent.alerts : []) as ScenarioBundle["alerts"],
    events,
    iocs: (Array.isArray(answerKey.iocs) ? answerKey.iocs : []) as IOC[],
    killchain: (Array.isArray(answerKey.killchain) ? answerKey.killchain : []) as ScenarioBundle["killchain"],
    questions,
  };
}
