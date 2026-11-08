// Attack-story prose moves with its event when the feed re-stamps it, so the row's
// time column and "signed in at 09:45" in its text agree.
import { describe, it, expect } from "vitest";
import { mapTimestamps, shiftClockText, storyTimeMap, withMappedTime, withRebasedTime } from "./rebaseTime";

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

describe("every instant inside a raw block moves (Sdema review K6)", () => {
  const d = 3_600_000;
  it("ISO with and without a zone, the space form and an offset keep their shape", () => {
    const out = withRebasedTime({ ts: "2026-09-22T08:00:00Z", raw: {
      a: "2026-09-22T08:56:12", b: "2026-09-22 08:34:09", c: "2026-09-22T08:00:00.123+02:00", d: "2026-09-22T08:00:00.1234567Z",
    } }, "2026-09-22T09:00:00Z").raw as Record<string, string>;
    expect(out).toEqual({ a: "2026-09-22T09:56:12", b: "2026-09-22 09:34:09", c: "2026-09-22T09:00:00.123+02:00", d: "2026-09-22T09:00:00.1234567Z" });
  });
  it("a date-time inside text, mail headers, a syslog header and epoch fields", () => {
    const raw = mapTimestamps({
      "ExtendedProperties.Proxy record": "zscalernss-web 2026-09-24 10:26:23",
      "email.headers.received_0": "from mx by filter01; Mon, 15 Jun 2026 09:23:14 +0000",
      "event.original": "Apr 14 21:40:00 nix-bkp-01 sshd[1788]: Accepted publickey",
      timestamp: 1_790_000_000_000, created_at: "1790000000", bytes_out: 1_790_000_000,
    }, ms => ms + d, Date.parse("2026-04-14T21:40:00Z")) as Record<string, unknown>;
    expect(raw["ExtendedProperties.Proxy record"]).toBe("zscalernss-web 2026-09-24 11:26:23");
    expect(raw["email.headers.received_0"]).toBe("from mx by filter01; Mon, 15 Jun 2026 10:23:14 +0000");
    expect(raw["event.original"]).toBe("Apr 14 22:40:00 nix-bkp-01 sshd[1788]: Accepted publickey");
    expect(raw.timestamp).toBe(1_790_000_000_000 + d);
    expect(raw.created_at).toBe(String(1_790_000_000 + 3600));
    expect(raw.bytes_out).toBe(1_790_000_000);   // not a time key: a byte count stays
  });
  it("clocks move only in the incident's free-text fields, never in a policy, a window or a command", () => {
    const raw = mapTimestamps({
      "servicenow.work_notes": "09:38: owner phoned; replayed the 08:31 recording",
      "ExtendedProperties.Usual Logon Hours": "08:00-19:00", "ExtendedProperties.Query Period": "00:10:00",
      "process.command_line": "schtasks /create /sc daily /st 07:50",
    }, ms => ms + d, Date.parse("2026-09-22T09:41:00Z")) as Record<string, unknown>;
    expect(raw["servicenow.work_notes"]).toBe("10:38: owner phoned; replayed the 09:31 recording");
    expect(raw["ExtendedProperties.Usual Logon Hours"]).toBe("08:00-19:00");
    expect(raw["ExtendedProperties.Query Period"]).toBe("00:10:00");
    expect(raw["process.command_line"]).toBe("schtasks /create /sc daily /st 07:50");
  });
});

describe("storyTimeMap: one monotone map per story", () => {
  const t0 = Date.parse("2026-09-22T08:00:00Z"), s0 = Date.parse("2026-01-01T08:00:00Z");
  const f = storyTimeMap([
    { authoredMs: t0, shownMs: s0 }, { authoredMs: t0 + 60 * 60_000, shownMs: s0 + 6 * 60_000 }, { authoredMs: t0 + 100 * 60_000, shownMs: s0 + 10 * 60_000 },
  ]);
  it("hits every row, interpolates between rows, keeps the authored distance outside", () => {
    expect(f(t0)).toBe(s0);
    expect(f(t0 + 30 * 60_000)).toBe(s0 + 3 * 60_000);
    expect(f(t0 + 100 * 60_000)).toBe(s0 + 10 * 60_000);
    expect(f(t0 - 30 * 86_400_000)).toBe(s0 - 30 * 86_400_000);   // "created 30 days ago" stays 30 days ago
    expect(f(t0 + 110 * 60_000)).toBe(s0 + 20 * 60_000);
  });
  it("is non-decreasing even when a row is shown out of authored order", () => {
    const g = storyTimeMap([{ authoredMs: 0, shownMs: 100 }, { authoredMs: 10, shownMs: 50 }, { authoredMs: 20, shownMs: 200 }]);
    const xs = [-5, 0, 5, 10, 15, 20, 25].map(g);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));
  });
  it("withMappedTime: the row's own time becomes its new ts, a time naming another row lands on that row", () => {
    const e = { ts: new Date(t0 + 100 * 60_000).toISOString(), raw: { "ExtendedProperties.MethodsDeletedTime": new Date(t0 + 60 * 60_000).toISOString(), TimeGenerated: new Date(t0 + 100 * 60_000).toISOString() } };
    const out = withMappedTime(e, new Date(s0 + 10 * 60_000 + 500).toISOString(), f).raw as Record<string, string>;
    expect(out["ExtendedProperties.MethodsDeletedTime"]).toBe(new Date(s0 + 6 * 60_000).toISOString());
    expect(out.TimeGenerated).toBe(new Date(s0 + 10 * 60_000 + 500).toISOString());
  });
});
