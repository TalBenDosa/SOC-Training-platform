/**
 * R7 brute force proof: failures as rows, or failures a record counts itself (ATTEMPT_COUNT_FIELDS).
 */
import { describe, expect, it } from "vitest";
import type { TelemetryEvent } from "@/lib/sim/types";
import type { LogRow } from "../types";
import { countedAttempts, r7 } from "./r7";

const T0 = Date.parse("2026-09-17T08:06:00Z");
function row(id: string, ev: Partial<TelemetryEvent>, raw: Record<string, unknown>, min = 0): LogRow {
  const e = { id, ts: new Date(T0 + min * 60_000).toISOString(), source: "app_log", event_type: "http_request", severity: "low", ...ev } as TelemetryEvent;
  return { surface: "team", company: "rocketstack", storyId: "s1", rowId: `s1:${id}`, source: String(e.source), eventType: e.event_type, time: T0 + min * 60_000, raw, ev: e, meta: { incident: "inc1" } };
}
const gql = (id: string, n: number, min: number) =>
  row(id, { mitre_technique: "T1110.001", network: { status: 200 } }, { "graphql.operationName": "SignIn", "graphql.aliasCount": n, "graphql.errors.UNAUTHENTICATED": n }, min);
const run = (rows: LogRow[]) => r7({ rows, feeds: [], notes: [] }).filter(v => v.rule === "R7");

describe("R7 counts failed guesses a record counts itself", () => {
  it("reads only the declared count fields, as positive integers", () => {
    expect(countedAttempts(gql("a", 250, 0))).toBe(250);
    expect(countedAttempts(row("b", {}, { "graphql.aliasCount": 250 }))).toBe(0);           // aliases are requests, not failures
    expect(countedAttempts(row("c", {}, { "graphql.errors.UNAUTHENTICATED": "x" }))).toBe(0);
    expect(countedAttempts(row("d", {}, { "graphql.errors.UNAUTHENTICATED": 0 }))).toBe(0);
  });
  it("a batched brute force whose records count 999 failed guesses in four HTTP 200s is provable", () => {
    expect(run([gql("g1", 250, 0), gql("g2", 250, 0.4), gql("g3", 250, 0.8), gql("g4", 249, 1.2)])).toEqual([]);
  });
  it("still needs 10 attempts in all: rows and counted guesses together", () => {
    const few = run([gql("g1", 3, 0), gql("g2", 3, 0.4)]);
    expect(few.map(v => v.detail)).toEqual(["brute force not provable: fewer than 10 failures"]);
    const fail = (i: number) => row(`f${i}`, { event_type: "auth_failure", mitre_technique: "T1110.001", user_email: "x@rocketstack.io" }, {}, i * 0.1);
    expect(run([gql("g1", 4, 0), ...[1, 2, 3, 4, 5, 6].map(fail)])).toEqual([]);
  });
  it("a spray is not proven by a count: it needs the accounts as rows", () => {
    const spray = [gql("g1", 250, 0), gql("g2", 250, 0.4)].map(r => ({ ...r, ev: { ...r.ev!, mitre_technique: "T1110.003" } }));
    expect(run(spray).map(v => v.detail)).toEqual(["spray not provable: fewer than 10 failures over 8 accounts"]);
  });
});
