/**
 * Cross-host entity correlation for the scenario investigation table
 * (team-exercise finding #14).
 *
 * "Correlate" used to highlight the rows that share the clicked row's
 * `incident_id`. Every multi-host-intrusion incident is one host, so it never
 * crossed a host boundary — while tying three hosts into one campaign is the
 * exact skill the scenario teaches. Analysts correlate by ENTITY: the same user,
 * IP, file hash or hostname appearing on several hosts.
 *
 * This module extracts those entities from every event (typed fields AND the raw
 * vendor block), normalises the vendor spellings so they join
 * (`n.harel@nexacorp.com` ≡ `NEXACORP\n.harel` ≡ `n.harel`; `FS-SRV-03.corp.local`
 * ≡ `FS-SRV-03`), and answers "which events, on which hosts, carry this entity".
 * It also builds the unified cross-host timeline.
 *
 * Pure; unit-tested in correlate.test.ts.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import { flattenEvent } from "./logSearch";

export type EntityType = "user" | "ip" | "hash" | "host";

export interface Entity {
  type: EntityType;
  /** Normalised join key (lower/upper-cased, domain-stripped). */
  key: string;
  /** A human-readable spelling seen in the logs. */
  display: string;
}

export const entityId = (e: Pick<Entity, "type" | "key">) => `${e.type}:${e.key}`;

const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;
const SHA256_RE = /^[a-f0-9]{64}$/i;
const HEX_RE = /^[a-f0-9]{32}$|^[a-f0-9]{40}$/i;

/** Values that name no one: service identities, placeholders, anonymous. */
const NOISE_USERS = new Set([
  "", "-", "n/a", "na", "none", "null", "unknown", "system", "nt authority\\system",
  "local service", "network service", "anonymous logon", "anonymous", "localsystem",
  "nt authority\\local service", "nt authority\\network service", "root",
]);

export function normaliseUser(raw: string): string | null {
  let v = raw.trim().toLowerCase();
  if (NOISE_USERS.has(v)) return null;
  if (v.includes("\\")) v = v.slice(v.lastIndexOf("\\") + 1); // DOMAIN\user
  if (v.includes("@")) v = v.slice(0, v.indexOf("@"));         // user@domain
  if (!v || NOISE_USERS.has(v) || v.endsWith("$")) return null; // machine accounts
  if (IPV4_RE.test(v) || v.length > 64) return null;
  return v;
}

export function normaliseHost(raw: string): string | null {
  const v = raw.trim();
  if (!v || v === "-" || IPV4_RE.test(v) || /\s/.test(v) || v.includes("/")) return null;
  const short = v.split(".")[0].toUpperCase();
  return short && short !== "LOCALHOST" ? short : null;
}

const lastSeg = (key: string) => {
  const s = key.split(".");
  return s[s.length - 1].toLowerCase().replace(/[^a-z0-9]/g, "");
};

function isUserKey(key: string): boolean {
  const lk = key.toLowerCase();
  if (/(^|\.)user\.(name|email|id)$/.test(lk)) return true; // ECS user.name / source.user.name
  const l = lastSeg(key);
  if (l.includes("sid") || l.includes("domain") || l.includes("agent") || l.includes("type") || l.includes("id") && !l.endsWith("userid")) return false;
  return l === "user" || l === "useremail" || l.endsWith("username") || l === "user_name" || l === "accountname"
    || l === "userid" || l.endsWith("userprincipalname") || l === "upn" || l === "email" || l === "sourceusername" || l === "actor";
}

function isHostKey(key: string): boolean {
  const l = lastSeg(key);
  const lk = key.toLowerCase();
  return l === "hostname" || l === "computername" || l === "computer" || l === "workstationname"
    || l === "devicename" || lk === "raw.host.name" || lk.endsWith(".host.name") || l === "srcmachinename";
}

function isHashKey(key: string): boolean {
  const l = lastSeg(key);
  return l.includes("sha256") || l.includes("sha1") || l.includes("md5") || l.includes("hash");
}

/**
 * Every correlatable entity an event carries, de-duplicated. The event's own
 * `hostname` is always included so a pivot can report which hosts it spans.
 */
export function extractEntities(ev: TelemetryEvent): Entity[] {
  const out = new Map<string, Entity>();
  const add = (type: EntityType, key: string | null, display: string) => {
    if (!key) return;
    const id = `${type}:${key}`;
    if (!out.has(id)) out.set(id, { type, key, display });
  };

  for (const { key, value } of flattenEvent(ev)) {
    const v = value.trim();
    if (!v) continue;
    // Skip platform bookkeeping — these are not observables.
    if (/^(id|ts|incident_id|edr_scope|tier|event_type|source|vendor|severity)$/.test(key)) continue;

    if (IPV4_RE.test(v)) {
      // Unspecified / loopback / broadcast addresses join everything to everything.
      if (!/^(0\.0\.0\.0|127\.|255\.255\.255\.255)/.test(v)) add("ip", v, v);
      continue;
    }
    if (SHA256_RE.test(v)) { add("hash", v.toLowerCase(), v.toLowerCase()); continue; }
    if (HEX_RE.test(v) && isHashKey(key)) { add("hash", v.toLowerCase(), v.toLowerCase()); continue; }
    if (isHostKey(key)) { add("host", normaliseHost(v), normaliseHost(v) ?? v); continue; }
    if (isUserKey(key)) {
      const u = normaliseUser(v);
      add("user", u, u ?? v);
    }
  }
  return [...out.values()];
}

export interface EntityStats {
  entity: Entity;
  eventIds: string[];
  hosts: string[];
}

export interface EntityIndex {
  /** entityId → stats across the whole scenario. */
  byEntity: Map<string, EntityStats>;
  /** event id → entity ids it carries. */
  byEvent: Map<string, string[]>;
}

const hostOf = (ev: TelemetryEvent) => (ev.hostname ? normaliseHost(ev.hostname) ?? ev.hostname : "—");

/** Index every entity of every event. */
export function buildEntityIndex(events: readonly TelemetryEvent[]): EntityIndex {
  const byEntity = new Map<string, EntityStats>();
  const byEvent = new Map<string, string[]>();
  for (const ev of events) {
    const ents = extractEntities(ev);
    const ids: string[] = [];
    const host = hostOf(ev);
    for (const ent of ents) {
      const id = entityId(ent);
      ids.push(id);
      let st = byEntity.get(id);
      if (!st) { st = { entity: ent, eventIds: [], hosts: [] }; byEntity.set(id, st); }
      st.eventIds.push(ev.id);
      if (!st.hosts.includes(host)) st.hosts.push(host);
    }
    byEvent.set(ev.id, ids);
  }
  return { byEntity, byEvent };
}

const ENTITY_ORDER: Record<EntityType, number> = { user: 0, host: 1, ip: 2, hash: 3 };

/**
 * The pivots worth offering from one event: its entities that appear in at
 * least one OTHER event, most cross-host first. A value seen only on this row
 * correlates nothing.
 */
export function pivotsForEvent(index: EntityIndex, eventId: string): EntityStats[] {
  const ids = index.byEvent.get(eventId) ?? [];
  return ids
    .map(id => index.byEntity.get(id)!)
    .filter(st => st && st.eventIds.length > 1)
    .sort((a, b) =>
      b.hosts.length - a.hosts.length
      || b.eventIds.length - a.eventIds.length
      || ENTITY_ORDER[a.entity.type] - ENTITY_ORDER[b.entity.type]);
}

const tsOf = (e: Pick<TelemetryEvent, "ts">) => new Date(e.ts).getTime();

/** Every event carrying the entity, in time order, across all hosts. */
export function eventsForEntity<T extends TelemetryEvent>(events: readonly T[], index: EntityIndex, id: string): T[] {
  const ids = new Set(index.byEntity.get(id)?.eventIds ?? []);
  return events.filter(e => ids.has(e.id)).sort((a, b) => tsOf(a) - tsOf(b));
}

export interface TimelineEntry<T> {
  event: T;
  host: string;
  /** Seconds since the first entry — lets the UI show gaps ("+15m"). */
  offsetSec: number;
}

/** A unified, time-sorted timeline across every host (optionally a subset). */
export function crossHostTimeline<T extends TelemetryEvent>(events: readonly T[]): TimelineEntry<T>[] {
  const sorted = [...events].sort((a, b) => tsOf(a) - tsOf(b) || a.id.localeCompare(b.id));
  const t0 = sorted.length ? tsOf(sorted[0]) : 0;
  return sorted.map(ev => ({ event: ev, host: hostOf(ev), offsetSec: Math.round((tsOf(ev) - t0) / 1000) }));
}
