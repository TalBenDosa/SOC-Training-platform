/**
 * Tier-3 close-out (T3 interface spec, stage E): after containment, the Tier-3 writes down how the
 * attacker got in, where it started, what to remove, which accounts to reset, what to block, and one
 * detection rule that would have caught it earlier.
 *
 * Event (migration 0115, Tier-3, running):
 *   t3.closeout { vector, first_host, remove: number[] (finding seqs), reset: string[], block: string[],
 *                 detection: string (a feed search query), notes }
 * PURE and isomorphic: the console builds and previews it, the report grades it (computeReport).
 */
import type { Ev } from "./types";
import type { LiveEvent } from "@/app/(app)/dashboard/useLiveEvents";
import { eventMatchesSearch } from "@/app/(app)/dashboard/eventSearch";
import { asStr } from "./format";

export type Vector = "email" | "download" | "account" | "exposed_service" | "cannot_determine";
export const VECTOR_LABEL: Record<Vector, string> = {
  email: "Email (phishing, attachment or link)",
  download: "Download or drive-by (a file the user ran)",
  account: "Stolen or guessed account",
  exposed_service: "Exposed service (VPN, web app, RDP)",
  cannot_determine: "Cannot determine from the evidence",
};

/** ATT&CK initial-access technique -> the close-out's vector class (null = not one of them). */
export function vectorOfTechnique(technique: string): Exclude<Vector, "cannot_determine"> | null {
  const t = technique.toUpperCase();
  if (/^T1566/.test(t) || /^T1534/.test(t)) return "email";
  if (/^T1189/.test(t) || /^T1204/.test(t) || /^T1195/.test(t)) return "download";
  if (/^T1078/.test(t) || /^T1110/.test(t) || /^T1621/.test(t) || /^T1528/.test(t) || /^T1550/.test(t)) return "account";
  if (/^T1190/.test(t) || /^T1133/.test(t) || /^T1210/.test(t)) return "exposed_service";
  return null;
}

/** Techniques that leave something behind to remove. */
export const PERSISTENCE_TECH = /^(T1053|T1547|T1543|T1136|T1098|T1546|T1037|T1505|T1574|T1197)/i;

export interface Closeout {
  seq: number; by: string | null; vector: Vector; firstHost: string;
  remove: number[]; reset: string[]; block: string[]; detection: string; notes: string;
}

export function closeoutsOf(events: Ev[]): Closeout[] {
  return events.filter(e => e.type === "t3.closeout").map(e => {
    const p = (e.payload ?? {}) as Record<string, unknown>;
    const v = asStr(p.vector) as Vector;
    const list = (x: unknown) => (Array.isArray(x) ? x.map(asStr).map(s => s.trim()).filter(Boolean) : []);
    return {
      seq: e.seq, by: e.actor_id, vector: v in VECTOR_LABEL ? v : "cannot_determine", firstHost: asStr(p.first_host),
      remove: (Array.isArray(p.remove) ? p.remove : []).map(Number).filter(Number.isFinite),
      reset: list(p.reset), block: list(p.block), detection: asStr(p.detection).slice(0, 300), notes: asStr(p.notes).slice(0, 1000),
    };
  });
}

/** How many logs in the feed a detection query matches, and on which hosts (the console's preview). */
export function detectionPreview(feed: Ev[], query: string): { rows: number; hosts: string[] } {
  const q = query.trim();
  if (q.length < 3) return { rows: 0, hosts: [] };
  let rows = 0; const hosts = new Set<string>();
  for (const f of feed) {
    const ev = f.payload as unknown as LiveEvent;
    if (!eventMatchesSearch(ev, q)) continue;
    rows++;
    const h = asStr((f.payload as { hostname?: unknown }).hostname);
    if (h) hosts.add(h);
  }
  return { rows, hosts: [...hosts].slice(0, 12) };
}

/** The close-out opens once a host has been isolated or a readiness verdict signed. */
export function closeoutOpen(events: Ev[]): boolean {
  return events.some(e => e.type === "edr.host_isolated" || e.type === "t3.readiness" || e.type === "containment.executed");
}
