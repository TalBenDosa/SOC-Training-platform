import { describe, expect, it } from "vitest";
import { deriveReadyMap } from "./lobbyReady";

const roster = [
  { user_id: "a", status: "invited" },
  { user_id: "b", status: "invited" },
  { user_id: "c", status: "ready" },
];

describe("deriveReadyMap — the lobby ready-check", () => {
  it("starts from the roster status read at load", () => {
    expect(deriveReadyMap(roster, [])).toEqual({ a: false, b: false, c: true });
  });

  it("applies member.ready / member.unready in seq order, whatever order they arrived in", () => {
    const ev = [
      { seq: 3, type: "member.ready", actor_id: "a" },
      { seq: 1, type: "member.ready", actor_id: "a" },
      { seq: 2, type: "member.unready", actor_id: "a" },
    ];
    expect(deriveReadyMap(roster, ev).a).toBe(true);
  });

  it("keeps everyone ready as the last player readies up (the reported bug)", () => {
    const ev = [
      { seq: 1, type: "member.ready", actor_id: "a" },
      { seq: 2, type: "member.ready", actor_id: "b" },
      { seq: 3, type: "event.opened", actor_id: "b" },   // unrelated traffic never resets anyone
    ];
    expect(deriveReadyMap(roster, ev)).toEqual({ a: true, b: true, c: true });
  });

  it("shows my click immediately, then defers to the server row once merged", () => {
    expect(deriveReadyMap(roster, [], { id: "a" }, true).a).toBe(true);
    // server rejected the action → pending cleared → back to the server's truth
    expect(deriveReadyMap(roster, [], { id: "a" }, null).a).toBe(false);
    // server accepted → its row is merged and pending is cleared
    expect(deriveReadyMap(roster, [{ seq: 5, type: "member.ready", actor_id: "a" }], { id: "a" }, null).a).toBe(true);
  });

  it("ignores events without an actor", () => {
    expect(deriveReadyMap(roster, [{ seq: 1, type: "member.ready", actor_id: null }])).toEqual({ a: false, b: false, c: true });
  });
});
