import { describe, it, expect } from "vitest";
import {
  loadInvestigationStart, saveInvestigationStart, clearInvestigationStart, elapsedSeconds, clockKey, MAX_RESUME_MS,
} from "./investigationClock";

function memStore() {
  const m = new Map<string, string>();
  return {
    getItem: (k: string) => m.get(k) ?? null,
    setItem: (k: string, v: string) => { m.set(k, v); },
    removeItem: (k: string) => { m.delete(k); },
    m,
  };
}

describe("investigation clock (#27)", () => {
  it("persists per scenario and resumes after reload", () => {
    const s = memStore();
    saveInvestigationStart("multi-host-intrusion", 1_000_000, s);
    expect(s.m.get(clockKey("multi-host-intrusion"))).toBe("1000000");
    expect(loadInvestigationStart("multi-host-intrusion", 1_060_000, s)).toBe(1_000_000);
    expect(loadInvestigationStart("other", 1_060_000, s)).toBeNull();
  });
  it("elapsed is wall time since start", () => {
    expect(elapsedSeconds(1_000_000, 1_000_000 + 5 * 60_000 + 999)).toBe(300);
    expect(elapsedSeconds(null)).toBe(0);
    expect(elapsedSeconds(2_000, 1_000)).toBe(0);
  });
  it("ignores stale, future or garbage values", () => {
    const s = memStore();
    s.setItem(clockKey("a"), "garbage");
    expect(loadInvestigationStart("a", 5_000, s)).toBeNull();
    saveInvestigationStart("a", 1, s);
    expect(loadInvestigationStart("a", 1 + MAX_RESUME_MS + 1, s)).toBeNull();
    saveInvestigationStart("a", 10_000_000, s);
    expect(loadInvestigationStart("a", 1_000, s)).toBeNull();
  });
  it("clears, and survives a throwing storage", () => {
    const s = memStore();
    saveInvestigationStart("a", 5, s);
    clearInvestigationStart("a", s);
    expect(s.m.size).toBe(0);
    const bad = {
      getItem: () => { throw new Error("x"); },
      setItem: () => { throw new Error("x"); },
      removeItem: () => { throw new Error("x"); },
    };
    expect(loadInvestigationStart("a", 10, bad)).toBeNull();
    expect(() => saveInvestigationStart("a", 5, bad)).not.toThrow();
    expect(() => clearInvestigationStart("a", bad)).not.toThrow();
  });
});
