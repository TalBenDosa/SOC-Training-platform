import { describe, it, expect } from "vitest";
import { resolveLocation } from "./resolveLocation";
import { browserSummary } from "./labels";

describe("resolveLocation — what the triage inbox shows for a report", () => {
  it("a room task names the room, the task position and type, what was on screen, and links to the room", () => {
    const l = resolveLocation("room_task", "encoding-encryption-hashing:enc-ac1", { category: "content" });
    expect(l.kindLabel).toBe("Learning room");
    expect(l.crumbs).toEqual(["Learning room", expect.stringContaining("Encoding, Encryption & Hashing")]);
    expect(l.step).toMatch(/^Task 5 of \d+ · Analyst verdict$/);
    expect(l.shown).toContain("Scheduled Task");
    expect(l.href).toBe("/rooms/encoding-encryption-hashing");
  });

  it("an old report (room / task_index / task_type context only) still resolves from the room data", () => {
    const l = resolveLocation("room_task", "encoding-encryption-hashing:enc-ac1", { room: "Encoding", task_index: "5", task_type: "analyst_choice" });
    expect(l.step).toMatch(/^Task 5 of/);
  });

  it("an unknown (org-authored) room falls back to the context the client sent", () => {
    const l = resolveLocation("room_task", "org-room-x:t3", { room: "Our Phishing Room", task_index: "3", task_type: "question" });
    expect(l.crumbs).toEqual(["Learning room", "Our Phishing Room"]);
    expect(l.step).toBe("Task 3 · Question");
  });

  it("a lesson names the path, module and lesson, keeps the page step, and links to the lesson", () => {
    const l = resolveLocation("lesson", "soc-analyst--tier-model-and-slas", { step: "Page 2 of 9", shown: "Escalation: Handing Off With Context" });
    expect(l.crumbs[0]).toBe("Learning path");
    expect(l.crumbs.at(-1)).toMatch(/Tier model/i);
    expect(l.step).toBe("Page 2 of 9");
    expect(l.href).toBe("/learn/soc-analyst/tier-model-and-slas");
  });

  it("a technical report shows the page, a readable browser and the screen size", () => {
    const l = resolveLocation("other", "technical", { category: "technical", page: "/dashboard", viewport: "1280x720",
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36" });
    expect(l.kind).toBe("technical");
    expect(l.href).toBe("/dashboard");
    expect(l.details).toEqual(expect.arrayContaining([{ label: "Browser", value: "Chrome 141 on Windows" }, { label: "Screen", value: "1280x720" }]));
  });

  it("never returns an answer key: only what the learner was shown", () => {
    const l = resolveLocation("room_task", "encoding-encryption-hashing:enc-ac1", {});
    expect(JSON.stringify(l)).not.toMatch(/false_positive|correct_verdict|explanation/i);
  });

  it("summarises common browsers", () => {
    expect(browserSummary("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15")).toBe("Safari 18 on macOS");
    expect(browserSummary("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0")).toBe("Edge 141 on Windows");
  });
});
