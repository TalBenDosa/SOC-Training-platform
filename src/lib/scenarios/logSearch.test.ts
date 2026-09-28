import { describe, it, expect } from "vitest";
import { parseSearchQuery, matchesQuery, searchEvents, fieldMatches } from "./logSearch";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";

const b = buildMultiHostIntrusionScenario();
const ids = (q: string) => searchEvents(b.events, q).map(e => e.id);
const HEX64 = /^[a-f0-9]{64}$/i;

describe("parseSearchQuery", () => {
  it("splits terms, field:value, quotes and negation", () => {
    expect(parseSearchQuery('user:svc_backup "R:\\stage" -firewall lsass')).toEqual([
      { field: "user", value: "svc_backup", negate: false },
      { field: null, value: "r:\\stage", negate: false },
      { field: null, value: "firewall", negate: true },
      { field: null, value: "lsass", negate: false },
    ]);
  });
  it("does not mistake a drive letter or URL scheme for a field", () => {
    expect(parseSearchQuery("C:\\Windows https://x.test/a")).toEqual([
      { field: null, value: "c:\\windows", negate: false },
      { field: null, value: "https://x.test/a", negate: false },
    ]);
  });
  it("keeps a time like 18:40 as a free-text term", () => {
    expect(parseSearchQuery("18:40")).toEqual([{ field: null, value: "18:40", negate: false }]);
  });
});

describe("full-text search over the raw record", () => {
  it("finds values that only exist in the raw block (report #13 misses)", () => {
    for (const q of ["10.20.6.28", "svc_backup", "lsass", "rclone"]) {
      expect(ids(q).length, q).toBeGreaterThan(0);
    }
  });
  it("finds a file hash, bare and as hash:<prefix>", () => {
    const withHash = b.events.find(e => e.file?.sha256 || Object.values(e.raw ?? {}).some(v => typeof v === "string" && HEX64.test(v)))!;
    const hash = (withHash.file?.sha256 ?? Object.values(withHash.raw).find(v => typeof v === "string" && HEX64.test(v))) as string;
    expect(ids(hash)).toContain(withHash.id);
    expect(ids(`hash:${hash.slice(0, 16)}`)).toContain(withHash.id);
  });
  it("matches field names too", () => {
    expect(ids("GrantedAccess").length).toBeGreaterThan(0);
  });
  it("ANDs terms and honours negation", () => {
    const all = ids("svc_backup");
    const noFw = ids("svc_backup -firewall");
    expect(noFw.length).toBeLessThanOrEqual(all.length);
    expect(ids("lsass zzzz-not-there")).toEqual([]);
  });
});

describe("field:value syntax", () => {
  it("user:svc_backup matches only events whose user fields carry it", () => {
    const hits = searchEvents(b.events, "user:svc_backup");
    expect(hits.length).toBeGreaterThan(0);
    for (const e of hits) expect(JSON.stringify(e).toLowerCase()).toContain("svc_backup");
    // svc_backup never touched the workstation.
    expect(hits.every(e => e.hostname !== "FIN-WS-08")).toBe(true);
  });
  it("src_ip / dst_ip aliases", () => {
    expect(ids("src_ip:10.20.6.28").length).toBeGreaterThan(0);
    for (const e of searchEvents(b.events, "dst_ip:10.20.6.28")) {
      expect(e.dst_ip === "10.20.6.28" || JSON.stringify(e.raw).includes("10.20.6.28")).toBe(true);
    }
  });
  it("host: alias", () => {
    expect(searchEvents(b.events, "host:FS-SRV-03").length).toBeGreaterThan(0);
  });
  it("fieldMatches resolves aliases and dotted suffixes", () => {
    expect(fieldMatches("raw.crowdstrike.UserName", "user")).toBe(true);
    expect(fieldMatches("user_email", "user")).toBe(true);
    expect(fieldMatches("raw.crowdstrike.UserName", "crowdstrike.UserName")).toBe(true);
    expect(fieldMatches("dst_ip", "dst_ip")).toBe(true);
    expect(fieldMatches("raw.destination.ip", "dst_ip")).toBe(true);
    expect(fieldMatches("src_ip", "dst_ip")).toBe(false);
    expect(fieldMatches("file.sha256", "hash")).toBe(true);
    expect(fieldMatches("raw.description", "ip")).toBe(false);
  });
  it("an empty query matches everything", () => {
    expect(searchEvents(b.events, "   ").length).toBe(b.events.length);
    expect(matchesQuery(b.events[0], [])).toBe(true);
  });
});
