/**
 * Scenarios page collector (/scenarios/[slug]).
 *
 * For every built-in scenario (SCENARIOS, which includes the scenario packs and their
 * scenarioEvents), builds the bundle, applies the same withholding the page applies before the
 * client sees it (conclusion raw keys dropped, incident ids assigned), and renders each event with
 * nativeStoryRenderer(bundle.events) exactly as ScenarioClient does. An event with no native
 * module shows its raw block.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { nativeStoryRenderer } from "@/lib/logs/native";
import { isConclusionRawKey } from "@/lib/scenarios/withheld";
import { incidentIdFor } from "@/lib/scenarios/incidentGroups";
import type { Collected, LogRow } from "../types";
import { legacySource, legacyType } from "./live";

export function scenarioIsAttack(e: TelemetryEvent): boolean {
  if (e.is_baseline || e.fp_explanation || e.it_verify_result === "confirmed") return false;
  if (e.expected_verdict === "fp" || e.expected_verdict === "informational") return false;
  if (e.expected_verdict === "tp" || e.expected_verdict === "escalate") return true;
  return !!e.mitre_technique;
}

/** The events of a scenario as the page hands them to the client (answer key withheld). */
export function scenarioClientEvents(slug: string, events: TelemetryEvent[]): TelemetryEvent[] {
  const anyIncident = events.some(e => !!e.incident_id);
  return events.map(e => {
    const raw: Record<string, unknown> = { ...(e.raw ?? {}) };
    for (const k of Object.keys(raw)) if (isConclusionRawKey(k)) delete raw[k];
    return { ...e, incident_id: incidentIdFor(e, slug, anyIncident), raw };
  });
}

export function collectScenarios(out: Collected): { slug: string; events: TelemetryEvent[]; full: TelemetryEvent[] }[] {
  const built: { slug: string; events: TelemetryEvent[]; full: TelemetryEvent[] }[] = [];
  let n = 0;
  for (const sc of SCENARIOS) {
    let full: TelemetryEvent[];
    try { full = sc.build().events ?? []; } catch { out.notes.push(`scenario ${sc.slug}: build failed`); continue; }
    const events = scenarioClientEvents(sc.slug, full);
    const render = nativeStoryRenderer(events);
    events.forEach((ev, i) => {
      const truth = full[i];
      const v = (() => { try { return render(ev); } catch { return null; } })();
      const base: Partial<LogRow> = {
        surface: "scenario", storyId: sc.slug, rowId: `${sc.slug}:${ev.id}`, time: Date.parse(ev.ts), isAttack: scenarioIsAttack(truth),
        severity: ev.severity, ev: truth, storyIndex: i, authoredTime: Date.parse(truth.ts),
      };
      const row: LogRow = v
        ? { ...base, source: v.log.sourceId, vendor: v.product, eventType: v.log.kind, raw: v.log.record, text: v.log.rawLine, native: v.log } as LogRow
        : { ...base, source: legacySource(ev), vendor: ev.vendor, eventType: legacyType(ev), raw: ev.raw ?? {} } as LogRow;
      out.rows.push(row);
      n++;
    });
    built.push({ slug: sc.slug, events, full });
  }
  out.notes.push(`scenario: ${built.length} scenarios, ${n} rows`);
  return built;
}
