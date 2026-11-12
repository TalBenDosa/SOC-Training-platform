/**
 * Which feed tag a Windows event log row carries (Tal's QA, 2026-11-12: a 4624 on WS-HR-1142 tagged
 * "Active Directory" next to a 4625 on the same workstation tagged "Windows Security", and a System-log
 * 7045 tagged "Windows Security").
 *
 * One rule, by who WROTE the record:
 *  - "windows_system": the System channel (7045, a service installed: Service Control Manager);
 *  - "ad":             the domain controller's Security log (any event a DC writes: Kerberos 4768-4771,
 *                      credential validation 4776, lockouts 4740, directory access / changes 4662 / 5136 /
 *                      5137, account and group management), or any event logged on a DC;
 *  - "windows_security": the Security log of a member workstation or server (logons on that machine,
 *                      process creation, share access, scheduled tasks ...).
 * A row with no Windows event id (an identity-protection alert filed under "ad") keeps its own source.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

/** Written only by a domain controller. */
const DC_EVENTS = new Set(["4768", "4769", "4770", "4771", "4776", "4740", "4662", "5136", "5137", "4741", "4742", "4743",
  "4720", "4722", "4723", "4724", "4725", "4726", "4738", "4767", "4728", "4729", "4732", "4733", "4756", "4757", "4886", "4887"]);
const isDcHost = (h?: string) => !!h && /(^|[-_])DC\d*($|[-_.])/i.test(h);

export function windowsEventId(ev: TelemetryEvent): string | undefined {
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const id = r["winlog.event_id"] ?? r["event.code"];
  return id !== undefined && /^\d{3,5}$/.test(String(id)) ? String(id) : undefined;
}

export function windowsFeedSource(ev: TelemetryEvent): "ad" | "windows_security" | "windows_system" | undefined {
  if (ev.source !== "ad" && ev.source !== "windows_security") return undefined;
  const id = windowsEventId(ev);
  if (!id) return undefined;
  if (id === "7045") return "windows_system";
  const host = ev.hostname ?? String((ev.raw ?? {})["host.name"] ?? "");
  if (DC_EVENTS.has(id) && (isDcHost(host) || !host)) return "ad";
  if (isDcHost(host)) return "ad";
  return "windows_security";
}
