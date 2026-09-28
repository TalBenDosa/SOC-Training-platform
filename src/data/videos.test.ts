import { describe, it, expect } from "vitest";
import { isYouTubeId, type VideoRef } from "@/lib/media/videos";
import { ROOM_VIDEOS, ROOM_TASK_VIDEOS } from "./roomVideos";
import { LESSON_VIDEOS } from "./lessonVideos";
import { ROOMS_META } from "./roomsMeta";
import { LESSON_PATHS } from "@/lib/lessons/paths";

// Integrity of the curated explainer-video maps (FB-008). A typo'd room id,
// task id or lesson key would silently render nothing, and a malformed video id
// would render a broken embed — both are caught here.

function assertValidRef(v: VideoRef, where: string) {
  expect(isYouTubeId(v.youtubeId), `${where}: bad youtubeId "${v.youtubeId}"`).toBe(true);
  expect(v.title.trim().length, `${where}: empty title`).toBeGreaterThan(0);
  expect(v.channel.trim().length, `${where}: empty channel`).toBeGreaterThan(0);
  if (v.minutes !== undefined) expect(v.minutes, `${where}: minutes`).toBeGreaterThan(0);
  if (v.startSec !== undefined) expect(v.startSec, `${where}: startSec`).toBeGreaterThanOrEqual(0);
}

const roomsById = new Map(ROOMS_META.map((r) => [r.id, r]));
const lessonKeys = new Set(
  LESSON_PATHS.flatMap((p) => p.modules.flatMap((m) => m.lessons.map((l) => `${p.slug}--${l.slug}`))),
);

describe("ROOM_VIDEOS", () => {
  it("has entries", () => {
    expect(Object.keys(ROOM_VIDEOS).length).toBeGreaterThan(0);
  });

  it.each(Object.entries(ROOM_VIDEOS))("%s → existing room with valid videos", (roomId, videos) => {
    expect(roomsById.has(roomId), `unknown room id "${roomId}"`).toBe(true);
    expect(videos.length).toBeGreaterThan(0);
    videos.forEach((v, i) => assertValidRef(v, `${roomId}[${i}]`));
  });
});

describe("ROOM_TASK_VIDEOS", () => {
  it.each(Object.entries(ROOM_TASK_VIDEOS))("%s → existing reading task with a valid video", (key, v) => {
    const [roomId, taskId, ...rest] = key.split(":");
    expect(rest.length, `key "${key}" must be "roomId:taskId"`).toBe(0);
    const room = roomsById.get(roomId);
    expect(room, `unknown room id "${roomId}"`).toBeDefined();
    const task = room!.tasks.find((t) => t.id === taskId);
    expect(task, `unknown task "${taskId}" in room "${roomId}"`).toBeDefined();
    expect(task!.type, `${key} should be a reading task`).toBe("reading");
    assertValidRef(v, key);
  });
});

describe("LESSON_VIDEOS", () => {
  it("has entries", () => {
    expect(Object.keys(LESSON_VIDEOS).length).toBeGreaterThan(0);
  });

  it.each(Object.entries(LESSON_VIDEOS))("%s → existing lesson with valid videos", (key, videos) => {
    expect(lessonKeys.has(key), `unknown lesson key "${key}"`).toBe(true);
    expect(videos.length).toBeGreaterThan(0);
    videos.forEach((v, i) => assertValidRef(v, `${key}[${i}]`));
  });
});
