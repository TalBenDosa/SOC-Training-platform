// XDR rows of the database audit and UEBA sources hold the values of the native feed record.
import { describe, expect, it } from "vitest";
import { corpus } from "@/lib/logs/native/testing/corpus";
import { nativeView } from "@/lib/logs/native";
import { SCENARIOS } from "@/lib/sim/scenarios";
import { nativeStoryRenderer } from "@/lib/logs/native";
import type { NativeLog } from "@/lib/logs/native/types";
import { mapRow } from "./mapRow";
import { columnType } from "./tables";

const SOURCES = new Set(["guardium", "mssql_audit", "mysql_audit", "exabeam", "securonix"]);
const ctx = { tenantId: "t" };

function logs(): NativeLog[] {
  const out: NativeLog[] = [];
  for (const c of corpus()) {
    if (c.ev.source !== "db_monitor" && c.ev.source !== "ueba") continue;
    const v = nativeView(c.ev, c.companyId);
    if (v && SOURCES.has(v.log.sourceId)) out.push(v.log);
  }
  for (const sc of SCENARIOS) {
    const evs = sc.build().events ?? [];
    const render = nativeStoryRenderer(evs);
    for (const ev of evs) if (ev.source === "db_monitor" || ev.source === "ueba") { const v = render(ev); if (v && SOURCES.has(v.log.sourceId)) out.push(v.log); }
  }
  return out;
}

describe("database audit and UEBA rows in the XDR workspace", () => {
  const all = logs();
  it("every native record of these sources lands in a real table", () => {
    expect(new Set(all.map(l => l.sourceId))).toEqual(SOURCES);
    for (const l of all) {
      const m = mapRow(l, ctx);
      expect(m, `${l.sourceId}/${l.kind}`).not.toBeNull();
      for (const col of Object.keys(m!.row)) expect(columnType(m!.table, col), `${m!.table}.${col}`).toBeDefined();
      expect(m!.row.TimeGenerated).toBe(new Date(l.timeMs).toISOString());
    }
  });
  it("Guardium: the Syslog message is the LEEF payload of the feed line", () => {
    for (const l of all.filter(x => x.sourceId === "guardium")) {
      const m = mapRow(l, ctx)!;
      expect(m.table).toBe("Syslog");
      expect(m.row.ProcessName).toBe("guard_sender");
      expect(l.rawLine!.endsWith(String(m.row.SyslogMessage))).toBe(true);
      expect(String(m.row.SyslogMessage)).toMatch(/^LEEF:1\.0\|IBM\|Guardium\|/);
      expect(String(m.row.SyslogMessage)).toContain(`|sql=${l.record.sql}|`);
    }
  });
  it("SQL Server Audit: event 33205 whose data lines are the record's columns", () => {
    for (const l of all.filter(x => x.sourceId === "mssql_audit")) {
      const m = mapRow(l, ctx)!;
      expect(m.table).toBe("Event");
      expect(m.row.EventID).toBe(33205);
      const text = String(m.row.RenderedDescription);
      for (const k of ["event_time", "action_id", "server_principal_name", "server_instance_name", "database_name", "object_name", "statement", "client_ip", "application_name"]) {
        expect(text, `${k}`).toContain(`${k}:${l.record[k] ?? ""}`);
      }
      expect(text).toContain(`succeeded:${l.record.succeeded === 1 ? "true" : "false"}`);
    }
  });
  it("MySQL / Exabeam / Securonix: the custom table keeps the record whole", () => {
    for (const l of all.filter(x => ["mysql_audit", "exabeam", "securonix"].includes(x.sourceId))) {
      const m = mapRow(l, ctx)!;
      expect(m.row.RawData).toEqual(l.record);
      expect(m.row.EventType).toBe(l.kind);
    }
  });
});
