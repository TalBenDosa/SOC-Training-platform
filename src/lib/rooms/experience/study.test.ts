import { describe, expect, it } from "vitest";
import type { SanitizedRoomTask } from "@/lib/rooms/sanitize";
import { readingFor, studyGroups } from "./study";

const tasks = [
  { id: "r1", type: "reading", heading: "One" },
  { id: "q1", type: "question" },
  { id: "r2", type: "reading", heading: "Two" },
  { id: "q2", type: "question" },
] as unknown as SanitizedRoomTask[];

describe("study guide", () => {
  it("opens the task's own reading, the nearest earlier one, or a pointer", () => {
    expect(readingFor("r2", tasks)).toBe("r2");
    expect(readingFor("q1", tasks)).toBe("r1");
    expect(readingFor("q2", tasks)).toBe("r2");
    expect(readingFor("q2", tasks, { q2: "r1" })).toBe("r1");
    expect(readingFor(undefined, tasks)).toBe("r1");
  });
  it("ignores a pointer to something that is not a reading", () => {
    expect(readingFor("q2", tasks, { q2: "q1" })).toBe("r2");
  });
  it("groups readings by station and keeps strays", () => {
    const g = studyGroups(tasks, [{ label: "A", taskIds: ["r1", "q1"] }]);
    expect(g.map(x => x.label)).toEqual(["A", "More"]);
    expect(g[1].entries[0].id).toBe("r2");
  });
});
