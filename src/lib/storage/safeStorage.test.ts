// QA phase 7, E-22: blocked or corrupt browser storage reads as "nothing stored".
import { describe, it, expect, vi, afterEach } from "vitest";
import { lsGet, lsSet, lsRemove, ssSet, lsReadJson, isStringArray } from "./safeStorage";

afterEach(() => { vi.restoreAllMocks(); localStorage.clear(); });

describe("safeStorage", () => {
  it("works normally when storage works", () => {
    expect(lsSet("k", "v")).toBe(true);
    expect(lsGet("k")).toBe("v");
    lsRemove("k");
    expect(lsGet("k")).toBeNull();
  });
  it("blocked storage (Safari private / site data off) never throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => { throw new DOMException("denied", "SecurityError"); });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("quota", "QuotaExceededError"); });
    vi.spyOn(Storage.prototype, "removeItem").mockImplementation(() => { throw new DOMException("denied", "SecurityError"); });
    expect(lsGet("k")).toBeNull();
    expect(lsSet("k", "v")).toBe(false);
    expect(ssSet("marker", "1")).toBe(false);   // ProgressProvider won't reload without the marker
    expect(() => lsRemove("k")).not.toThrow();
  });
  it("corrupt or wrong-shape JSON falls back", () => {
    localStorage.setItem("recent", "{not json");
    expect(lsReadJson("recent", [], isStringArray)).toEqual([]);
    localStorage.setItem("recent", JSON.stringify({ a: 1 }));
    expect(lsReadJson("recent", [], isStringArray)).toEqual([]);
    localStorage.setItem("recent", JSON.stringify(["a", "b"]));
    expect(lsReadJson("recent", [], isStringArray)).toEqual(["a", "b"]);
  });
});
