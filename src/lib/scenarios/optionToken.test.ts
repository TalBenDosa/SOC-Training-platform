import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { optionToken, decodeAnswer } from "./optionToken";

const q = { id: "q1", options: [{ value: "wrong_folder" }, { value: "right" }] };

describe("optionToken", () => {
  it("is deterministic, opaque and per slug/question", () => {
    const t = optionToken("s", "q1", "wrong_folder");
    expect(t).toBe(optionToken("s", "q1", "wrong_folder"));
    expect(t).not.toContain("wrong");
    expect(t).not.toBe(optionToken("s2", "q1", "wrong_folder"));
    expect(t).not.toBe(optionToken("s", "q2", "wrong_folder"));
  });
  it("decodes tokens and passes raw values through", () => {
    expect(decodeAnswer("s", q, optionToken("s", "q1", "right"))).toBe("right");
    expect(decodeAnswer("s", q, [optionToken("s", "q1", "right"), "wrong_folder"])).toEqual(["right", "wrong_folder"]);
    expect(decodeAnswer("s", q, "junk")).toBe("junk");
    expect(decodeAnswer("s", q, undefined)).toBeUndefined();
  });
});

describe("opaque event ids", () => {
  it("maps ids to stable opaque tokens and rewrites every whole-token mention", async () => {
    const { eventIdMap, maskEventIds } = await import("./optionToken");
    const m = eventIdMap("s", ["evt_ws3_beacon", "evt_ws3"]);
    expect(m.get("evt_ws3_beacon")).toMatch(/^ev-[0-9a-f]{10}$/);
    expect(eventIdMap("s", ["evt_ws3_beacon"]).get("evt_ws3_beacon")).toBe(m.get("evt_ws3_beacon"));
    const out = maskEventIds({ events: [{ id: "evt_ws3_beacon" }, { id: "evt_ws3" }], q: "Read evt_ws3_beacon and evt_ws3." }, m);
    expect(JSON.stringify(out)).not.toMatch(/evt_ws3/);
    expect(out.q).toBe(`Read ${m.get("evt_ws3_beacon")} and ${m.get("evt_ws3")}.`);
  });
});

describe("opaque event ids — short references", () => {
  it("maps a unique numbered short form to the same token as its full id", async () => {
    const { eventIdMap, maskEventIds } = await import("./optionToken");
    const m = eventIdMap("s", ["evt_ce_03_nsenter", "evt_ce_04_xmrig"]);
    const out = maskEventIds({ q: "Compare evt_ce_03 with evt_ce_04." }, m);
    expect(out.q).toBe(`Compare ${m.get("evt_ce_03_nsenter")} with ${m.get("evt_ce_04_xmrig")}.`);
  });
});
