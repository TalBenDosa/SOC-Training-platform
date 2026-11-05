import { describe, it, expect } from "vitest";
import { ROOMS } from "@/data/rooms";
import { ROOM_NARRATION, NARRATION_BASE } from "@/data/roomNarration";
import { roomNarrationSrc } from "./roomNarration";

const readings = ROOMS.flatMap(r => r.tasks.filter(t => t.type === "reading").map(t => ({ room: r.id, t: t as Extract<typeof t, { type: "reading" }> })));
const spoken = (t: { heading: string; content: string }) => `${t.heading}.\n\n${t.content}`;

describe("room narration (neural voice recordings)", () => {
  it("every recording belongs to an existing room reading and has a valid fingerprint", () => {
    const keys = new Set(readings.map(r => `${r.room}/${r.t.id}`));
    for (const [k, e] of Object.entries(ROOM_NARRATION)) {
      expect(keys.has(k), k).toBe(true);
      expect(e.h).toMatch(/^[0-9a-f]{8}$/);
      expect(e.v).toMatch(/^en-US-(Ava|Andrew|Emma|Brian)MultilingualNeural$/);
    }
  });

  it("plays the recording only while the reading text is unchanged", () => {
    const r = readings.find(x => ROOM_NARRATION[`${x.room}/${x.t.id}`])!;
    const src = roomNarrationSrc(r.room, r.t.id, spoken(r.t));
    expect(src).toBe(`${NARRATION_BASE}/${r.room}/${r.t.id}-${ROOM_NARRATION[`${r.room}/${r.t.id}`].h}.mp3`);
    // An edited reading falls back to the browser voice instead of playing stale audio.
    expect(roomNarrationSrc(r.room, r.t.id, spoken(r.t) + " Edited.")).toBeUndefined();
    expect(roomNarrationSrc("no-such-room", "x", "text")).toBeUndefined();
  });

  it("keeps the recording through a punctuation fix, never through a changed word", () => {
    const r = readings.find(x => ROOM_NARRATION[`${x.room}/${x.t.id}`]?.w && roomNarrationSrc(x.room, x.t.id, spoken(x.t)))!;
    const swap = (from: string, to: string) => spoken({ heading: r.t.heading, content: r.t.content.replace(from, to) });
    const word = r.t.content.match(/[A-Za-z]{6,}/)![0];
    expect(roomNarrationSrc(r.room, r.t.id, swap(word, `${word},`))).toBeDefined();
    expect(roomNarrationSrc(r.room, r.t.id, swap(word, `${word}x`))).toBeUndefined();
  });

  it("covers the room readings (re-record after large content edits)", () => {
    const current = readings.filter(r => roomNarrationSrc(r.room, r.t.id, spoken(r.t))).length;
    // Fallback is safe, but most readings should have their neural recording.
    expect(current / readings.length).toBeGreaterThan(0.9);
  });
});
