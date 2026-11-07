/**
 * IOC truth after the 2026-11 review (iocs.md): real rows from the two exercises. A benign
 * address or file must not read malicious because it sits in an attack row, an abused signed
 * OS binary reads clean, and a hash on a host in hand is answered for the EDR console too.
 */
import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import rowsJson from "./__fixtures__/review2-ioc-rows.json";
import { buildTeamIocTruth, answerIocQuery, rowsOnHosts } from "./iocTruth";
import { iocDigest, type IocType } from "@/lib/edr/iocIntel";
import type { Ev } from "./types";

type Row = { payload: Record<string, unknown>; answer: Record<string, unknown> };
const rows = rowsJson as unknown as Record<string, Row>;
function session(prefix: string) {
  const picked = Object.entries(rows).filter(([k]) => k.startsWith(prefix));
  const events: Ev[] = picked.map(([k, r], i) => ({ seq: i + 1, type: "feed.event", actor_id: null, role: null, payload: { ...r.payload, inject_id: `inj-${k}` } }));
  const injects = picked.map(([k, r]) => ({ id: `inj-${k}`, channel: "feed", expected_action: r.answer }));
  return { events, injects };
}
const v = (truth: ReturnType<typeof buildTeamIocTruth>, type: IocType, value: string) => truth.entries[iocDigest(type, value)]?.v ?? "none";

describe("benign addresses in attack rows (iocs.md #1, #2)", () => {
  it("session 1: the webjob's managed-identity egress is clean, the attacker stays malicious", () => {
    const { events, injects } = session("session1");
    const truth = buildTeamIocTruth(events, injects);
    expect(v(truth, "ip", "20.50.73.84")).toBe("clean");
    expect(v(truth, "ip", "45.155.205.211")).toBe("malicious");
  });
  it("session 2: the assistant app's own egress is clean, the uploader and the C2 stay malicious", () => {
    const { events, injects } = session("session2");
    const truth = buildTeamIocTruth(events, injects);
    expect(v(truth, "ip", "198.51.100.84")).toBe("clean");
    expect(v(truth, "ip", "203.0.113.47")).toBe("malicious");
    expect(v(truth, "ip", "104.248.93.41")).toBe("malicious");
  });
});

describe("hashes (iocs.md #3, abused binaries)", () => {
  const { events, injects } = session("session2");
  const truth = buildTeamIocTruth(events, injects);
  it("the signed real app an installer drops is clean; the delivered installer and the unsigned keylogger stay malicious", () => {
    expect(v(truth, "hash", "477c0e33a5cdbd55b97f32a7ac512a02b1261ab624d98f721f836e543fecdd8f")).toBe("clean");      // SwiftPDF.exe
    expect(v(truth, "hash", "2db113d603fb0d89aa504fa6a7ffc002d64f674dca3e20f94030b3bb4e6c7a62")).toBe("malicious");  // SwiftPDF_Setup.exe
    expect(v(truth, "hash", "8dd7c76738e045bf5cdf44c557145e8d68fd46251349821cc4002f4254eedc7a")).toBe("malicious");  // winupd_helper.exe
  });
  it("an abused runtime (bash, node) is clean as a file, the same on every surface", () => {
    expect(["clean", "none"]).toContain(v(truth, "hash", "c4069c3b87b3698f3ae18f4602f869a7ddd7bf955c21aeebcf48f2b5b2dc7584"));  // bash
    expect(["clean", "none"]).toContain(v(truth, "hash", "85427add0401af37258ec324e4fbb48b13042888b2f3d9cbd0f6ce63e85fac2c"));  // node
  });
});

describe("the EDR console's hash reads like the drawer (iocs.md #4)", () => {
  const { events, injects } = session("session2");
  const truth = buildTeamIocTruth(events, injects);
  const installer = { type: "hash" as const, value: "2db113d603fb0d89aa504fa6a7ffc002d64f674dca3e20f94030b3bb4e6c7a62" };
  // The analyst opened only the row where the real app starts (#43), on WS-HR-1182.
  const inHand = events.filter(e => (e.payload as { process?: { name?: string } }).process?.name === "SwiftPDF.exe");
  it("without the host rows the installer hash is refused (what the console used to show as clean)", () => {
    const r = answerIocQuery(truth, [installer], inHand);
    expect(r.refused).toHaveLength(1);
  });
  it("with the rows on the host in hand it is answered malicious, as in the drawer", () => {
    const r = answerIocQuery(truth, [installer], inHand, rowsOnHosts(events, inHand));
    expect(r.entries[iocDigest("hash", installer.value)]?.v).toBe("malicious");
  });
  it("host rows open hashes only, never addresses", () => {
    const r = answerIocQuery(truth, [{ type: "ip", value: "85.209.11.37" }], [], rowsOnHosts(events, inHand));
    expect(r.refused).toHaveLength(1);
  });
});
