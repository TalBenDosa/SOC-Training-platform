// @vitest-environment jsdom
import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { getReadMarks, setReadMark, syncReadMarks } from "./readMarks";

const A = { userId: "u1", orgId: "orgA" };
const B = { userId: "u1", orgId: "orgB" };

describe("library read marks", () => {
  beforeEach(() => localStorage.clear());
  afterEach(() => vi.unstubAllGlobals());

  it("guests keep marks in this browser only, and never call the server", () => {
    const f = vi.fn();
    vi.stubGlobal("fetch", f);
    setReadMark({ userId: null }, "local-lesson-4", true);
    expect([...getReadMarks({ userId: null })]).toEqual(["local-lesson-4"]);
    expect(f).not.toHaveBeenCalled();
  });

  it("two organisations of the same learner never share marks", () => {
    vi.stubGlobal("fetch", vi.fn(() => Promise.resolve(new Response(null, { status: 204 }))));
    setReadMark(A, "local-lesson-4", true);
    expect(getReadMarks(A).has("local-lesson-4")).toBe(true);
    expect(getReadMarks(B).size).toBe(0);
  });

  it("a signed-in mark is sent to the server with the lesson and the state only", () => {
    const f = vi.fn(() => Promise.resolve(new Response(JSON.stringify({ saved: true }))));
    vi.stubGlobal("fetch", f);
    setReadMark(A, "local-lesson-5", true);
    setReadMark(A, "local-lesson-5", false);
    expect(f).toHaveBeenCalledTimes(2);
    const calls = f.mock.calls as unknown as [string, RequestInit][];
    expect(JSON.parse(String(calls[1][1].body))).toEqual({ lessonId: "local-lesson-5", studied: false });
    expect(getReadMarks(A).size).toBe(0);
  });

  it("sync merges the server copy and uploads marks only this browser has", async () => {
    localStorage.setItem("soc_track_read_v1:u2", JSON.stringify(["local-lesson-9"])); // pre-0111 copy
    const posted: string[] = [];
    vi.stubGlobal("fetch", vi.fn((_url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(String(init.body)).lessonId);
        return Promise.resolve(new Response(JSON.stringify({ saved: true })));
      }
      return Promise.resolve(new Response(JSON.stringify({ ids: ["local-lesson-3"] })));
    }));
    const who = { userId: "u2", orgId: "orgA" };
    await syncReadMarks(who);
    expect(posted).toEqual(["local-lesson-9"]);
    expect([...getReadMarks(who)].sort()).toEqual(["local-lesson-3", "local-lesson-9"]);
    expect(localStorage.getItem("soc_track_read_v1:u2")).toBeNull();
  });

  it("a server without the table leaves the browser copy untouched", async () => {
    const who = { userId: "u3", orgId: "orgA" };
    localStorage.setItem("soc_track_read_v1:u3:orgA", JSON.stringify(["local-lesson-6"]));
    const f = vi.fn(() => Promise.resolve(new Response(JSON.stringify({ ids: [], unavailable: true }))));
    vi.stubGlobal("fetch", f);
    await syncReadMarks(who);
    expect(f).toHaveBeenCalledTimes(1);
    expect([...getReadMarks(who)]).toEqual(["local-lesson-6"]);
  });
});
