import type { TelemetryEvent } from "@/lib/sim/types";
import type { EdrInvestigation } from "@/lib/edr/investigations";
import type { IocTruth } from "@/lib/edr/iocIntel";
import { buildInvestigationFromStory } from "@/lib/edr/fromLiveStory";
import { hostKey } from "@/lib/team/format";

/**
 * The EDR cases a Team-SOC analyst opens — ONE PER HOST. A team feed interleaves
 * every host of the shift (two concurrent incidents plus background noise), so
 * building a single investigation from the whole feed opened whichever host had the
 * most process telemetry — often not the host of the case the analyst clicked.
 * Each case is built only from that host's own logs.
 *
 * `hosts` empty (the console-header button with no case in hand) → one case for the
 * whole feed, as before. Hosts with no endpoint telemetry yield no case.
 */
export function buildTeamEdrCases(
  events: TelemetryEvent[],
  opts: { sessionId: string; hosts: string[]; description?: string; iocTruth?: IocTruth | null },
): EdrInvestigation[] {
  const seen = new Set<string>();
  const out: EdrInvestigation[] = [];
  for (const h of opts.hosts) {
    const k = hostKey(h);
    if (!k || seen.has(k)) continue;
    seen.add(k);
    const own = events.filter(e => e.hostname && hostKey(e.hostname) === k);
    const inv = buildInvestigationFromStory({ id: `team-${opts.sessionId}-${k}`, title: `Escalated case — ${h}`, events: own, iocTruth: opts.iocTruth ?? null });
    // The builder names every case "live"; several hosts in one console need distinct ids.
    if (inv) out.push({ ...inv, id: `team-${opts.sessionId}-${k}` });
  }
  if (opts.hosts.length === 0) {
    const inv = buildInvestigationFromStory({ id: `team-${opts.sessionId}`, title: "Team incident — live", events, iocTruth: opts.iocTruth ?? null });
    if (inv) out.push({ ...inv, id: `team-${opts.sessionId}` });
  }
  // The description of the case the analyst clicked heads the console.
  if (opts.description && out.length === 1) out[0].title = opts.description;
  return out;
}
