// QA phase 7, E-06: background failures surface as one level on /superadmin.
import { describe, it, expect } from "vitest";
import { opsLevel } from "./opsHealth";

const base = { running_sessions: 2, paused_sessions: 0, max_promote_lag_s: 0, ops_errors_1h: 0, broadcast_failures_1h: 0 };

describe("opsLevel", () => {
  it("quiet → ok, no reasons", () => expect(opsLevel(base)).toEqual({ level: "ok", reasons: [] }));
  it("a few broadcast failures → warning; many → critical", () => {
    expect(opsLevel({ ...base, broadcast_failures_1h: 3, ops_errors_1h: 3 }).level).toBe("warning");
    expect(opsLevel({ ...base, broadcast_failures_1h: 25, ops_errors_1h: 25 }).level).toBe("critical");
  });
  it("stalled injects are flagged; numeric strings from PostgREST work", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const r = opsLevel({ ...base, max_promote_lag_s: "400.5" as any });
    expect(r.level).toBe("critical");
    expect(r.reasons[0]).toMatch(/401 s late/);
  });
  it("no data is a warning, never 'ok'", () => expect(opsLevel(null).level).toBe("warning"));
});
