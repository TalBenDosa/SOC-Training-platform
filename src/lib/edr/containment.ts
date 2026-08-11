/**
 * Shared containment state between the EDR console and the live SOC Dashboard —
 * the "one platform" feel. When a student network-contains a host in /edr, the
 * Dashboard reflects it (a "contained in EDR" indicator), exactly as isolating a
 * host in Falcon shows up across the console. Backed by localStorage + a window
 * event so both surfaces react without a server round-trip.
 */
const KEY = "edr_contained_hosts";
export const EDR_CONTAINMENT_EVENT = "edr:containment-changed";

function read(): string[] {
  if (typeof window === "undefined") return [];
  try { return JSON.parse(localStorage.getItem(KEY) || "[]"); } catch { return []; }
}

function write(hosts: string[]) {
  if (typeof window === "undefined") return;
  localStorage.setItem(KEY, JSON.stringify([...new Set(hosts)]));
  window.dispatchEvent(new CustomEvent(EDR_CONTAINMENT_EVENT));
}

export function containedHosts(): string[] {
  return read();
}

export function isContained(host: string): boolean {
  return read().includes(host);
}

export function setContained(host: string, contained: boolean): void {
  const cur = read();
  write(contained ? [...cur, host] : cur.filter(h => h !== host));
}
