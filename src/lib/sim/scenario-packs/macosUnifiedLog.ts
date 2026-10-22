/**
 * macOS Unified Log emitter (scenario-local companion for macosTccPkg).
 *
 * The Unified Log is what `log show --style ndjson` prints on a Mac: one JSON object per
 * record with the keys below. A packaged-install story needs two of them (syspolicyd's
 * Gatekeeper assessment and the installer's signature check), and no shared emitter
 * exists for the Unified Log, so the scenario renders them here instead of hand-typing a
 * `raw` block in the pack. Only keys that `log show` really writes are used.
 *
 * Source "siem": a forwarded Mac log has no EDR product behind it, so it must not be
 * rendered as a Falcon record.
 */
import type { TelemetryEvent, Severity } from "@/lib/sim/types";

export interface MacosUnifiedLogOpts {
  id: string;
  ts: string;                     // ISO, with milliseconds
  host: string;
  srcIp?: string;
  incidentId?: string;
  processImagePath: string;       // the logging process, e.g. /usr/libexec/syspolicyd
  processId: number;
  subsystem: string;              // e.g. com.apple.syspolicy
  category: string;
  eventMessage: string;
  messageType?: "Default" | "Info" | "Debug" | "Error" | "Fault";
  severity?: Severity;
  description: string;
}

/** `2026-08-28 14:29:58.118204+0000`, the timestamp format of `log show`. */
function logTimestamp(iso: string): string {
  const m = iso.match(/^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})\.(\d{3})Z$/);
  return m ? `${m[1]} ${m[2]}.${m[3]}000+0000` : iso;
}

export function macosUnifiedLog(o: MacosUnifiedLogOpts): TelemetryEvent {
  const record: Record<string, string | number> = {
    timestamp: logTimestamp(o.ts),
    eventMessage: o.eventMessage,
    eventType: "logEvent",
    messageType: o.messageType ?? "Default",
    subsystem: o.subsystem,
    category: o.category,
    processImagePath: o.processImagePath,
    processID: o.processId,
    senderImagePath: o.processImagePath,
    timezoneName: "",
  };
  return {
    id: o.id, ts: o.ts, source: "siem", vendor: "macOS Unified Log", event_type: "privileged_operation",
    severity: o.severity ?? "informational", hostname: o.host, src_ip: o.srcIp, incident_id: o.incidentId,
    description: o.description,
    raw: record,
  };
}
