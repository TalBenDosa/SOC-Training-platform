import { describe, it, expect } from "vitest";
import {
  buildEntityIndex, extractEntities, pivotsForEvent, eventsForEntity, crossHostTimeline,
  normaliseUser, normaliseHost, entityId,
} from "./correlate";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";

const b = buildMultiHostIntrusionScenario();
const index = buildEntityIndex(b.events);

describe("normalisation", () => {
  it("joins vendor spellings of one user", () => {
    expect(normaliseUser("n.harel@nexacorp.com")).toBe("n.harel");
    expect(normaliseUser("NEXACORP\\n.harel")).toBe("n.harel");
    expect(normaliseUser("n.harel")).toBe("n.harel");
  });
  it("drops non-person identities", () => {
    for (const v of ["SYSTEM", "NT AUTHORITY\\SYSTEM", "-", "FS-SRV-03$", "ANONYMOUS LOGON"]) expect(normaliseUser(v)).toBeNull();
  });
  it("short-names hosts", () => {
    expect(normaliseHost("fs-srv-03.corp.example")).toBe("FS-SRV-03");
    expect(normaliseHost("10.20.7.33")).toBeNull();
  });
});

describe("cross-host pivots on multi-host-intrusion", () => {
  it("the victim user spans more than one host", () => {
    const st = index.byEntity.get(entityId({ type: "user", key: "n.harel" }));
    expect(st).toBeDefined();
    expect(st!.hosts.length).toBeGreaterThan(1);
  });
  it("the workstation IP links the foothold host to the file server", () => {
    const st = index.byEntity.get(entityId({ type: "ip", key: "10.20.6.28" }))!;
    expect(st.hosts).toEqual(expect.arrayContaining(["FIN-WS-08", "FS-SRV-03"]));
  });
  it("pivots from an FS-SRV-03 event lead with a cross-host entity", () => {
    const logon = b.events.find(e => e.id === "evt_mhi_fs1_logon") ?? b.events.find(e => e.hostname === "FS-SRV-03")!;
    const piv = pivotsForEvent(index, logon.id);
    expect(piv.length).toBeGreaterThan(0);
    expect(piv[0].hosts.length).toBeGreaterThan(1);
    // Only entities seen in another event are offered.
    for (const p of piv) expect(p.eventIds.length).toBeGreaterThan(1);
  });
  it("eventsForEntity returns time-sorted events across hosts", () => {
    const evs = eventsForEntity(b.events, index, entityId({ type: "user", key: "n.harel" }));
    const ts = evs.map(e => new Date(e.ts).getTime());
    expect([...ts].sort((a, c) => a - c)).toEqual(ts);
    expect(new Set(evs.map(e => e.hostname)).size).toBeGreaterThan(1);
  });
  it("a hash entity is extracted from the renamed-rclone events and joins them", () => {
    const stage = b.events.find(e => /svchost-update/i.test(e.process?.name ?? ""))!;
    const hash = extractEntities(stage).find(en => en.type === "hash");
    expect(hash).toBeDefined();
    expect(index.byEntity.get(entityId(hash!))!.eventIds.length).toBeGreaterThan(1);
  });
});

describe("crossHostTimeline", () => {
  it("sorts every event by time with a host column and offsets", () => {
    const tl = crossHostTimeline(b.events);
    expect(tl.length).toBe(b.events.length);
    for (let i = 1; i < tl.length; i++) {
      expect(new Date(tl[i].event.ts).getTime()).toBeGreaterThanOrEqual(new Date(tl[i - 1].event.ts).getTime());
    }
    expect(tl[0].offsetSec).toBe(0);
    expect(new Set(tl.map(t => t.host)).size).toBe(3);
  });
});
