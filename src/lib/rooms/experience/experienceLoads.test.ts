// Every room with an Operation Mode experience must actually load it. A station
// taskId list that drifts from the room's own task ids (count, membership or
// order) makes getRoomExperience return null, which silently drops the room back
// to Classic. labIntegrity.test.ts filters out rooms whose experience is null, so
// that failure used to pass unnoticed (2026-11 rooms report: web-application-security
// had 13 station ids for a 15-task room). This guard catches it directly.
import { describe, it, expect } from "vitest";
import { ROOMS } from "@/data/rooms";
import { getRoomExperience, registeredExperienceRoomIds } from "./index";

describe("Operation Mode experiences load", () => {
  for (const roomId of registeredExperienceRoomIds()) {
    it(`${roomId}: station task ids match the room`, () => {
      const room = ROOMS.find(r => r.id === roomId);
      expect(room, `room ${roomId} is in the experience registry but not in ROOMS`).toBeTruthy();
      const exp = getRoomExperience(roomId, room!.tasks.map(t => t.id));
      expect(exp, `experience for ${roomId} did not load: its station task ids must equal the room's task ids, in order`).not.toBeNull();
    });
  }
});
