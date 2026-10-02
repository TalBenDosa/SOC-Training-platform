import type { TelemetryEvent } from "@/lib/sim/types";

/**
 * One host, one IP — and never one IP for two hosts — across a feed pool.
 *
 * The authored noise pools were written event by event, so the same workstation shows
 * up with two or three addresses (WH-TERM-005: .5 / .44 / .82) and two hosts sometimes
 * share one. The first pivot an analyst makes — "what else did this IP / this host do?" —
 * then lies. Each host keeps its most frequent outbound address; an address another host
 * already owns moves to a free one in the same /24. Only host-originated events change
 * (a host's own telemetry, its outbound network rows), and the old address is replaced
 * in that event's raw fields too, so the record agrees with the row.
 */
const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/;
const HOSTISH = new Set(["edr", "sysmon", "av", "windows_security", "linux_audit", "firewall", "proxy", "dns"]);
const inbound = (e: TelemetryEvent) =>
  (e.network as { direction?: string } | undefined)?.direction === "inbound" || /inbound/i.test(String(e.raw?.["network.direction"] ?? ""));
const hostOwned = (e: TelemetryEvent) => !!e.hostname && !!e.src_ip && PRIVATE.test(e.src_ip) && HOSTISH.has(e.source) && !inbound(e);

export function normalizeHostIps(events: TelemetryEvent[]): TelemetryEvent[] {
  const counts = new Map<string, Map<string, number>>();
  for (const e of events) {
    if (!hostOwned(e)) continue;
    const h = e.hostname!.toUpperCase();
    const m = counts.get(h) ?? new Map<string, number>();
    m.set(e.src_ip!, (m.get(e.src_ip!) ?? 0) + 1);
    counts.set(h, m);
  }
  const owner = new Map<string, string>();   // ip → host
  const canonical = new Map<string, string>();
  // Hosts with the most evidence claim their address first.
  const hosts = [...counts].sort((a, b) => Math.max(...b[1].values()) - Math.max(...a[1].values()) || a[0].localeCompare(b[0]));
  const allIps = new Set(events.flatMap(e => [e.src_ip, e.dst_ip]).filter((x): x is string => !!x && PRIVATE.test(x)));
  for (const [h, m] of hosts) {
    const ranked = [...m].sort((a, b) => b[1] - a[1]).map(([ip]) => ip);
    let ip = ranked.find(x => !owner.has(x));
    if (!ip) {
      const base = ranked[0].split(".").slice(0, 3).join(".");
      for (let i = 2; i < 255 && !ip; i++) { const c = `${base}.${i}`; if (!owner.has(c) && !allIps.has(c)) ip = c; }
      ip = ip ?? ranked[0];
    }
    owner.set(ip, h); canonical.set(h, ip);
  }
  return events.map(e => {
    if (!hostOwned(e)) return e;
    const want = canonical.get(e.hostname!.toUpperCase());
    if (!want || want === e.src_ip) return e;
    const old = e.src_ip!;
    const raw = e.raw ? Object.fromEntries(Object.entries(e.raw).map(([k, v]) => [k, v === old ? want : v])) : e.raw;
    return { ...e, src_ip: want, raw };
  });
}
