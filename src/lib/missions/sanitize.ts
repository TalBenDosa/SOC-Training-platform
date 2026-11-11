/**
 * What of a mission reaches the browser: the story, the evidence (tables,
 * artefacts, files, events), the prompts and the two hints. Never: reference
 * queries, accepted values, traps, the shadow dataset, hidden corpora, the
 * worked answer or the debrief (those come back from the grader).
 */
import { stringCorpusCounts } from "./grade";
import { buildSample, extractStrings } from "./yara/samples";
import type { ConsoleStep, FieldsStep, IocStep, KqlStep, MissionField, MissionTask, ReportStep, RuleStep, StepWithXp, StringsStep } from "./types";

type Common = { xp: number; hint: string; where: string };

/** One line of the strings view, with the corpus vote: in how many known-bad and goodware files it appears. */
export interface StringRow { offset: number; enc: "ascii" | "wide"; value: string; bad: number; good: number }

export type SanitizedField = Omit<MissionField, "accept" | "tolerance" | "coach" | "traps">;
export type SanitizedStep =
  | (Omit<KqlStep, "answer"> & Common)
  | (Omit<FieldsStep, "fields"> & Common & { fields: SanitizedField[] })
  | (Omit<IocStep, "expect" | "forbidden"> & Common & { expectCount: number })
  | (StringsStep & Common & { view: StringRow[]; totals: { bad: number; good: number } })
  | (Omit<RuleStep, "hidden"> & Common & { hiddenCount: number })
  | (Omit<ReportStep, "slots"> & Common & { slots: Omit<ReportStep["slots"][number], "checks" | "forbidden">[] })
  | (Omit<ConsoleStep, "fields" | "expect"> & Common & { fields: SanitizedField[]; checksIncidents: string[] });

export type SanitizedMissionTask = Omit<MissionTask, "steps"> & { steps: SanitizedStep[] };

function sanitizeStep(s: StepWithXp, task: MissionTask): SanitizedStep {
  const common: Common = { xp: s.xp, hint: s.hint, where: s.where };
  switch (s.kind) {
    case "kql": {
      const { answer: _a, worked: _w, debrief: _d, solution: _s, ...rest } = s;
      return { ...rest, ...common };
    }
    case "fields": {
      const { worked: _w, debrief: _d, solution: _s, fields, ...rest } = s;
      return { ...rest, ...common, fields: fields.map(({ accept: _x, tolerance: _t, coach: _c, traps: _tr, ...f }) => f) };
    }
    case "iocs": {
      const { expect, forbidden: _f, worked: _w, debrief: _d, solution: _s, ...rest } = s;
      return { ...rest, ...common, expectCount: expect.length };
    }
    case "strings": {
      const { worked: _w, debrief: _d, solution: _s, ...rest } = s;
      // The corpus counts include the hidden files: "who else has this string" IS the evidence here.
      const counts = stringCorpusCounts(task);
      const sample = task.samples?.[s.sample];
      const view: StringRow[] = sample
        ? extractStrings(buildSample(sample.spec).bytes).map(x => ({ ...x, bad: counts.get(x.value)?.bad ?? 0, good: counts.get(x.value)?.good ?? 0 }))
        : [];
      const all = [...(task.samples ?? []), ...task.steps.flatMap(st => st.kind === "rule" ? st.hidden.samples ?? [] : [])];
      return { ...rest, ...common, view, totals: { bad: all.filter(x => x.label === "bad").length, good: all.filter(x => x.label === "good").length } };
    }
    case "rule": {
      const { hidden, worked: _w, debrief: _d, solution: _s, ...rest } = s;
      return { ...rest, ...common, hiddenCount: (hidden.samples?.length ?? 0) + (hidden.events?.length ?? 0) };
    }
    case "console": {
      const { fields, expect, worked: _w, debrief: _d, solution: _s, ...rest } = s;
      return {
        ...rest, ...common,
        fields: (fields ?? []).map(({ accept: _x, tolerance: _t, coach: _c, traps: _tr, ...f }) => f),
        // Which incidents the check reads (their numbers are on the screen anyway), never what it wants of them.
        checksIncidents: (expect ?? []).map(e => e.incidentId),
      };
    }
    case "report": {
      const { slots, worked: _w, debrief: _d, solution: _s, ...rest } = s;
      return { ...rest, ...common, slots: slots.map(({ checks: _c, forbidden: _f, ...slot }) => slot) };
    }
  }
}

export function sanitizeMission(task: MissionTask): SanitizedMissionTask {
  const { steps, ...rest } = task;
  return { ...rest, steps: steps.map(st => sanitizeStep(st, task)) };
}
