// Every practical mission in the curriculum, checked the way the SPEC asks (section 3.1 "Integrity test"):
//  - every step's solution passes, on the visible AND the shadow dataset (the grader runs both);
//  - a KQL step's answer differs between the two datasets (otherwise the shadow proves nothing),
//    and a query that hard-codes the visible answer fails;
//  - fixtures are fictional (.example domains, RFC 1918 / 203.0.113.x / 198.51.100.x / 185.220.101.45);
//  - nothing server-only reaches the sanitized payload;
//  - no em dashes.
import { describe, it, expect, vi } from "vitest";

vi.mock("server-only", () => ({}));
const { ROOMS } = await import("@/data/rooms");
const { gradeMissionStep } = await import("./grade");
const { sanitizeMission } = await import("./sanitize");
const { solutionFor } = await import("./solution");
const { runMissionQuery, cellKey } = await import("./kqlCompare");
const { getDataset } = await import("./datasets");
import type { MissionTask } from "./types";

const missions: { roomId: string; task: MissionTask }[] = ROOMS.flatMap(r =>
  r.tasks.filter((t): t is MissionTask => t.type === "mission").map(task => ({ roomId: r.id, task })));

const ALLOWED_IP = (ip: string) => /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  || /^203\.0\.113\./.test(ip) || /^198\.51\.100\./.test(ip) || /^192\.0\.2\./.test(ip) || ip === "185.220.101.45" || /^127\./.test(ip) || ip === "0.0.0.0"
  || /^\d+\.\d+\.\d+\.\d+$/.test(ip) && ip.split(".").some(o => Number(o) > 255);

describe("practical missions", () => {
  it("the pilot rooms carry missions", () => {
    expect(missions.length).toBeGreaterThan(0);
  });

  for (const { roomId, task } of missions) {
    describe(`${roomId}/${task.id}`, () => {
      it("every step's solution passes (visible + shadow)", () => {
        const bad: string[] = [];
        task.steps.forEach((s, i) => {
          const answer = solutionFor(task, i);
          if (!answer) { bad.push(`step ${i + 1} (${s.kind}): no solution`); return; }
          const g = gradeMissionStep(task, i, answer, 1, 0);
          if (!g.ok) bad.push(`step ${i + 1}: ${g.error}`);
          else if (!g.correct) bad.push(`step ${i + 1}: solution rejected ${JSON.stringify(g.reveal).slice(0, 300)}`);
          else if (g.xpEarned !== s.xp) bad.push(`step ${i + 1}: first-try XP ${g.xpEarned} != ${s.xp}`);
        });
        expect(bad).toEqual([]);
      });

      it("KQL steps: answers differ on the shadow data, and hard-coding the visible answer fails", () => {
        const bad: string[] = [];
        task.steps.forEach((s, i) => {
          if (s.kind !== "kql") return;
          const ds = task.dataset ? getDataset(task.dataset) : null;
          if (!ds) { bad.push(`step ${i + 1}: KQL step without a dataset`); return; }
          const ref = s.answer.reference[0];
          const a = runMissionQuery(ds.visible, ref), b = runMissionQuery(ds.shadow, ref);
          if (!a.ok || !b.ok) { bad.push(`step ${i + 1}: reference fails ${!a.ok ? a.error.message : ""} ${!b.ok ? b.error.message : ""}`); return; }
          if (a.rows.length === 0) bad.push(`step ${i + 1}: reference returns no rows on the visible data`);
          const key = (r: typeof a) => r.ok ? JSON.stringify(r.rows.map(row => s.answer.keys.map(k => cellKey(row[k], s.answer.tolerance))).sort()) : "";
          if (key(a) === key(b)) bad.push(`step ${i + 1}: same answer on visible and shadow data`);
          // The hard-coded answer: a datatable of the visible result passes nothing on the shadow.
          if (s.answer.mode === "values") {
            const vals = [...new Set(a.rows.map(r => String(r[s.answer.keys[0]])))];
            const firstTable = (/^\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(ref) ?? [])[1] ?? "";
            const hard = `${firstTable} | where ${s.answer.keys[0]} in (${vals.map(v => JSON.stringify(v)).join(", ")}) | distinct ${s.answer.keys[0]}`;
            const g = gradeMissionStep(task, i, { query: hard }, 1, 0);
            if (g.ok && g.correct) bad.push(`step ${i + 1}: a hard-coded query passes (${hard.slice(0, 120)})`);
          }
        });
        expect(bad).toEqual([]);
      });

      it("fixtures are fictional", () => {
        const ds = task.dataset ? getDataset(task.dataset) : null;
        const blob = JSON.stringify(task) + (ds ? JSON.stringify(ds.visible) + JSON.stringify(ds.shadow) : "");
        const ips = [...blob.matchAll(/(?<![\d./])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])/g)].map(m => m[1]);
        const realIps = [...new Set(ips.filter(ip => !ALLOWED_IP(ip)))];
        const domains = [...blob.matchAll(/\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|io|co|uk|ru|cn|info|biz|xyz|top))\b/gi)].map(m => m[1].toLowerCase());
        const allowedDomain = (d: string) => /(^|\.)(microsoft|windows|live|office|office365|outlook|azure|sharepoint|google|cloudflare)\.com$/.test(d)
          || /^(kernel32|ntdll|user32|advapi32)\./.test(d);
        const realDomains = [...new Set(domains.filter(d => !allowedDomain(d)))];
        expect({ realIps, realDomains }).toEqual({ realIps: [], realDomains: [] });
      });

      it("no em dashes", () => {
        const ds = task.dataset ? getDataset(task.dataset) : null;
        expect((JSON.stringify(task) + (ds ? JSON.stringify(ds.visible) : "")).includes(String.fromCharCode(0x2014))).toBe(false);
      });

      it("the sanitized payload holds no answers", () => {
        const safe = JSON.stringify(sanitizeMission(task));
        const leaks: string[] = [];
        for (const k of ['"reference"', '"accept"', '"worked"', '"debrief"', '"solution"', '"forbidden"', '"expect"', '"checks"', '"hidden"', '"traps"', '"coach"']) {
          if (safe.includes(k)) leaks.push(k);
        }
        for (const s of task.steps) {
          if (s.worked.length > 20 && safe.includes(JSON.stringify(s.worked).slice(1, -1))) leaks.push(`${s.id}: worked text`);
        }
        expect(leaks).toEqual([]);
      });
    });
  }
});
