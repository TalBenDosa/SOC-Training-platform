/**
 * The answer object that should pass a step, for the integrity tests: the
 * step's own `solution` when authored, else derived from its answer key.
 * Never used at runtime.
 */
import { stringCorpusCounts } from "./grade";
import type { MissionTask } from "./types";
import { buildSample, extractStrings } from "./yara/samples";

export function solutionFor(task: MissionTask, i: number): Record<string, unknown> | null {
  const s = task.steps[i];
  if (s.solution) return s.solution;
  switch (s.kind) {
    case "kql": return { query: s.answer.reference[0] };
    case "fields": return { values: Object.fromEntries(s.fields.map(f => [f.id, f.format === "set" ? f.accept.join(", ") : f.accept[0]])) };
    case "iocs": return { iocs: s.expect.map(e => ({ type: e.type, value: e.value })) };
    case "strings": {
      const sample = task.samples?.[s.sample];
      if (!sample) return null;
      const counts = stringCorpusCounts(task);
      const picks = extractStrings(buildSample(sample.spec).bytes).map(x => x.value)
        .filter(v => (counts.get(v)?.good ?? 1) === 0 && (counts.get(v)?.bad ?? 0) >= s.minBad);
      return { picks: [...new Set(picks)] };
    }
    case "rule": return null;
    case "report": return null;
  }
}
