/**
 * The solo Live Feed's ordinary-noise pool for one company: the company's own logs, only the
 * sources its architecture runs, no real attack hiding in the noise, one IP per host.
 * Pure (no React): the dashboard page, the realism tests and the feed playthrough share it.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { COMPANY_PROFILES, NEXACORP_PROFILE } from "@/lib/sim/companyProfilesMeta";
import { normalizeHostIps } from "@/lib/sim/hostIdentity";

export interface FeedPoolData {
  BENIGN_EVENTS: TelemetryEvent[];
  COMPANY_EVENTS: Record<string, TelemetryEvent[]>;
}

export function feedCompanyProfile(id: string) {
  return COMPANY_PROFILES.find(c => c.id === id) ?? { ...NEXACORP_PROFILE };
}

export function companyEventsRaw(sim: FeedPoolData, id: string): TelemetryEvent[] {
  const base = id === "nexacorp" ? sim.BENIGN_EVENTS : (sim.COMPANY_EVENTS[id] ?? sim.BENIGN_EVENTS);
  // L-03 / L-09: emit ONLY the sources this company's architecture actually runs.
  // The pool used to leak 12+ sources (a second competing EDR, AWS WAF/RDS on an
  // Azure estate, DLP/Linux/email that the company never declared) regardless of
  // the stack, which contradicts the Security-Products and Asset-Context rooms and
  // left the source filter menu (correctly limited to the declared sources) unable
  // to select half of what was on screen.
  const active = new Set(feedCompanyProfile(id).architecture?.sources ?? []);
  // E-12: DNS is the most common log source in any SOC, so it must appear in the
  // background noise. It is gated by the company's declared sources like every other source.
  // QA-DASH-4: the noise pool also carries real malicious events that Team mode scores as
  // "attacks hiding in the noise". The solo shift can only credit its injected story, so a
  // real attack in the solo noise could never be caught or debriefed. Solo noise is benign /
  // false-positive only.
  const isMalicious = (e: TelemetryEvent) => {
    const v = String((e as { expected_verdict?: unknown }).expected_verdict ?? "");
    return v === "tp" || v === "escalate";
  };
  return base.filter(e => (active.size === 0 || active.has(e.source)) && !isMalicious(e));
}

/** One host, one IP across the noise (normalizeHostIps), computed once per data set + company. */
const cache = new WeakMap<FeedPoolData, Map<string, TelemetryEvent[]>>();
export function companyFeedPool(sim: FeedPoolData, id: string): TelemetryEvent[] {
  const hit = cache.get(sim)?.get(id);
  if (hit) return hit;
  const out = normalizeHostIps(companyEventsRaw(sim, id));
  (cache.get(sim) ?? cache.set(sim, new Map()).get(sim)!).set(id, out);
  return out;
}
