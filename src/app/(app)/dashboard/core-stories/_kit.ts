/**
 * Shared helpers for the core attack catalog (identity, Active Directory, endpoint, cloud,
 * developer, email and network stories). Events only: this module ships in the browser
 * bundle like the rest of attackStories.ts, so nothing answer-bearing beyond the event
 * fields the pipeline already strips belongs here.
 */
import type { Severity, TelemetryEvent } from "@/lib/sim/types";
import type { SeatRole } from "@/lib/sim/companyProfilesMeta";
import { sysmonDriver } from "@/lib/sim/emitters/sysmon";
import { makeSha256 } from "@/lib/sim/iocs";
import { makeCtx } from "@/lib/logs/native/ctx";
import { testNetIp } from "@/lib/logs/native/sources/remote-access-shared";

export interface CoreStoryDef {
  id: string;
  title: string;
  complexity: "foundation" | "core" | "advanced";
  /** Explicit company allowlist. Omitted = the source-fit rule decides. */
  companies?: string[];
  /** The job the main person must hold: they and their machine come from the company's seats. */
  seat?: SeatRole;
  events: TelemetryEvent[];
}

/** Companies with a mail gateway product. RocketStack has none in its stack, so a gateway record there would name a product it does not run. Listed because QuantumBank's feed has no o365 channel key. */
export const MAIL_GATEWAY_COMPANIES = ["nexacorp", "medcore", "globallogis", "quantumbank"];
/** Companies running Entra ID and on-premises Active Directory. */
export const AD_COMPANIES = ["nexacorp", "medcore", "globallogis"];
/** Companies whose cloud estate is AWS. */
export const AWS_COMPANIES = ["rocketstack", "globallogis", "quantumbank"];
/** Companies whose cloud estate is Azure. */
export const AZURE_COMPANIES = ["nexacorp", "medcore"];

/** The office's public address, a documentation address per company: instantiateStory swaps it with the rest of a tenant's identity. */
export const OFFICE_EGRESS = testNetIp(makeCtx("nexacorp"), "nexacorp:egress");

/** A clock for one story: T(seconds after the story's start). */
export function clock(startIso: string): (sec: number) => string {
  const b = Date.parse(startIso);
  return sec => new Date(b + sec * 1000).toISOString();
}

/** Benign look-alike: the same record shape, innocent activity. The reason is answer data, stripped from public rows. */
export function lookalike(ev: TelemetryEvent, why: string): TelemetryEvent {
  const { mitre_technique: _m, mitre_tactic: _t, is_detection: _d, ...rest } = ev;
  return { ...rest, expected_verdict: "fp", fp_explanation: why };
}

/** Every row of a story belongs to one incident. */
export function incident(id: string, events: TelemetryEvent[]): TelemetryEvent[] {
  return events.map(e => ({ ...e, incident_id: e.incident_id ?? id }));
}

/** Sysmon Event 7, image loaded. Same base block as the driver emitter; the record is built by the sysmon module. */
export function sysmonImageLoad(o: {
  id: string; ts: string; companyId?: string; host: string; user: string; srcIp?: string;
  image: string; pid: number; parentName?: string; loaded: string; sha256?: string;
  signed: boolean; signature?: string; signatureStatus?: string;
  mitre?: string; tactic?: string; severity?: Severity; isDetection?: boolean; description: string;
}): TelemetryEvent {
  const sha256 = o.sha256 ?? makeSha256(`imageload:${o.loaded}`);
  const base = sysmonDriver({
    id: o.id, ts: o.ts, companyId: o.companyId, host: o.host, user: o.user, srcIp: o.srcIp, image: o.loaded, sha256,
    signed: o.signed, signature: o.signature, signatureStatus: o.signatureStatus,
    mitre: o.mitre, tactic: o.tactic, severity: o.severity, isDetection: o.isDetection, description: o.description,
  });
  const name = o.image.split("\\").pop() ?? o.image;
  return {
    ...base,
    event_type: "process_create",
    process: { name, pid: o.pid, path: o.image, parent_name: o.parentName },
    raw: { ...base.raw, "winlog.event_id": "7", "event.code": "7", "event.category": "library", "event.action": "image-loaded", "winlog.event_data.Image": o.image },
  };
}
