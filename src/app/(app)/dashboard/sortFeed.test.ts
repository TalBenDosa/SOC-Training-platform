// Tal, 2026-10-18: newest logs on top, or a switch to oldest first.
import { describe, it, expect } from "vitest";
import { sortFeed } from "./EventFeed";

const ev = (id: string, ts?: string) => ({ id, ts });
const feed = [ev("a", "2026-10-18T10:00:00Z"), ev("b", "2026-10-18T10:05:00Z"), ev("c", "2026-10-18T10:02:00Z")];

describe("sortFeed", () => {
  it("newest first / oldest first by event time", () => {
    expect(sortFeed(feed, "newest").map(e => e.id)).toEqual(["b", "c", "a"]);
    expect(sortFeed(feed, "oldest").map(e => e.id)).toEqual(["a", "c", "b"]);
  });
  it("rows without a time keep their arrival order (reversed for newest first)", () => {
    const noTs = [ev("x"), ev("y"), ev("z")];
    expect(sortFeed(noTs, "newest").map(e => e.id)).toEqual(["z", "y", "x"]);
    expect(sortFeed(noTs, "oldest").map(e => e.id)).toEqual(["x", "y", "z"]);
  });
});
