/**
 * The operating system a set of rows shows a host running (pure, no imports beyond types).
 * One reading for the story dealer (attackStories: a Windows story lands on a Windows desk) and the
 * noise deck (noiseDeck: a recurring MacBook row is re-homed only to another Mac).
 */
import type { TelemetryEvent } from "./types";
import type { HostOs } from "./companyProfilesMeta";

const MAC_PATH = /^\/(Applications|Users|Volumes|System|Library|private)\//;
const UNIX_PATH = /^\/(usr|bin|sbin|etc|home|opt|var|tmp|lib|snap)\//;
export const WIN_PATH = /^([a-z]:\\|\\Device\\|\\\\)/i;

export function osHint(e: TelemetryEvent): string {
  const r = (e.raw ?? {}) as Record<string, unknown>;
  return String(r["crowdstrike.event_platform"] ?? r["host.os.type"] ?? r["host.os.family"] ?? r["host.os.name"] ?? r["host.os.platform"] ?? "");
}

/**
 * macOS (platform, /Applications, /Users), Linux (auditd, platform, unix image paths) or Windows
 * (Security log, Sysmon, platform, Windows paths), from any of the rows on host `h`. Undefined when
 * no row says (a sign-in, a firewall session).
 */
export function hostOsFromRows(h: string, events: TelemetryEvent[]): HostOs | undefined {
  const on = events.filter(e => e.hostname === h);
  const paths = (e: TelemetryEvent) => [e.process?.path ?? "", e.file?.path ?? ""];
  if (on.some(e => /mac|darwin|osx/i.test(osHint(e)) || paths(e).some(p => MAC_PATH.test(p)))) return "mac";
  if (on.some(e => e.source === "linux_audit" || e.event_type === "linux_execve" || /^lin|linux|ubuntu|rhel|debian|centos/i.test(osHint(e)) || UNIX_PATH.test(e.process?.path ?? ""))) return "linux";
  if (on.some(e => e.source === "windows_security" || e.source === "sysmon" || /^win/i.test(osHint(e)) || paths(e).some(p => WIN_PATH.test(p)))) return "windows";
  return undefined;
}
