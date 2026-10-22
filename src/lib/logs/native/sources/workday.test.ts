import { describe, it, expect } from "vitest";
import { source, kindOf } from "./workday";
import { makeCtx } from "../ctx";
import { validateNative } from "../validate";
import { runUseCase } from "../engine";
import { nativize } from "../index";
import type { TelemetryEvent } from "@/lib/sim/types";

const resign: TelemetryEvent = {
  id: "wd1", ts: "2026-08-14T09:12:00.000Z", source: "hr", vendor: "Workday", event_type: "account_modify", severity: "low",
  user_email: "d.okafor@nexacorp.com",
  raw: { "workday.event_type": "Worker_Resignation_Submitted", "workday.worker_id": "WD-0071254", "workday.worker_email": "d.okafor@nexacorp.com",
    "workday.termination_date": "2026-08-28", "workday.initiated_by": "d.okafor@nexacorp.com" },
} as TelemetryEvent;
const terminate: TelemetryEvent = { ...resign, id: "wd2", raw: { ...resign.raw, "workday.event_type": "Worker_Termination_Initiated", "workday.initiated_by": "hr.operations@nexacorp.com" } } as TelemetryEvent;

describe("workday, activity log", () => {
  it("renders a valid activity record carrying the worker, the task and the effective date", () => {
    const log = source.fromTelemetry(resign, makeCtx("nexacorp"))!;
    expect(validateNative(log, source.schema)).toEqual([]);
    expect(kindOf(log.record)).toBe("activity");
    expect(log.record.taskDisplayName).toBe("Resign");
    expect(log.record.systemAccount).toBe("d.okafor");
    expect(String((log.record.target as { descriptor: string }).descriptor)).toContain("08/28/2026");
    const t = source.fromTelemetry(terminate, makeCtx("nexacorp"))!;
    expect(t.record.taskDisplayName).toBe("Terminate Employee");
    expect(t.record.systemAccount).toBe("hr.operations");
  });
  it("is the record every stack shows for a Workday event, deterministically", () => {
    expect(nativize(resign, "nexacorp")?.sourceId).toBe("workday");
    expect(nativize(resign, "medcore", { idp: "okta" })?.sourceId).toBe("workday");
    expect(source.fromTelemetry(resign, makeCtx("nexacorp"))).toEqual(source.fromTelemetry(resign, makeCtx("nexacorp")));
  });
  it("use cases fire on departure tasks", () => {
    const logs = [resign, terminate].map(e => source.fromTelemetry(e, makeCtx("nexacorp"))!);
    for (const uc of source.useCases) expect(runUseCase(uc, logs).length, uc.id).toBeGreaterThan(0);
  });
});
