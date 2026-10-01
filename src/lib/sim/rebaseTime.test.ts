// Attack-story prose moves with its event when the feed re-stamps it, so the row's
// time column and "signed in at 09:45" in its text agree.
import { describe, it, expect } from "vitest";
import { shiftClockText, withRebasedTime } from "./rebaseTime";

const authored = Date.parse("2026-07-14T09:45:00Z");

describe("story clock text", () => {
  it("shifts the event's own clock times by the re-stamp delta", () => {
    const delta = Date.parse("2026-10-01T22:20:00Z") - authored;
    expect(shiftClockText("signed in to SharePoint Online at 09:45 from London", authored, delta, "utc"))
      .toBe("signed in to SharePoint Online at 22:20 from London");
    expect(shiftClockText("At 09:40 a POST; at 09:47:10 a second one", authored, delta, "utc"))
      .toBe("At 22:15 a POST; at 22:22:10 a second one");
  });
  it("crosses midnight to the nearest day", () => {
    const delta = Date.parse("2026-10-02T00:05:00Z") - Date.parse("2026-07-12T23:58:00Z");
    expect(shiftClockText("at 23:58 and again at 00:03", Date.parse("2026-07-12T23:58:00Z"), delta, "utc")).toBe("at 00:05 and again at 00:10");
  });
  it("leaves MACs, IPv6, versions and ratios alone", () => {
    const t = "MAC 00:15:5d:01:02:03, fe80::12:34, v10:22.1, ratio 16:9, port 10:443x";
    expect(shiftClockText(t, authored, 3_600_000, "utc")).toBe(t);
  });
  it("withRebasedTime only touches prose when asked (benign rows state schedules)", () => {
    const e = { ts: "2026-07-14T09:45:00Z", description: "job at 03:15 — scheduled end-of-day process", raw: {} };
    expect(withRebasedTime(e, "2026-10-01T22:20:00Z").description).toBe(e.description);
    expect(withRebasedTime({ ...e, description: "signed in at 09:45" }, "2026-10-01T22:20:00Z", { storyClock: "utc" }).description).toBe("signed in at 22:20");
  });
});
