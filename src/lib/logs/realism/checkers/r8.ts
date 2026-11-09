/**
 * R8 Realistic volume and severity, on the feeds a learner triages (Live Feed shifts per company and
 * story, Team sessions):
 *  a. Ordinary noise is at least twice the attack rows (live: over the story's window).
 *  b. Severity does not reveal the answer: per company, some benign row is high or critical and
 *     some attack row is low or informational.
 *  c. Repeated benign rows are drawn fresh: no 3 or more benign rows with identical content (times,
 *     guids and long ids aside) in one feed or noise pool.
 *  d. Tickets (ServiceNow records) are at most about 8% of a feed (8.5% allowed).
 */
import type { Checker, LogRow, Violation } from "../types";
import { contentKey } from "../util";

const isTicket = (r: LogRow) => r.source === "servicenow" || r.source.startsWith("legacy:") && /servicenow/i.test(r.vendor ?? "");
const HIGH = new Set(["high", "critical"]), LOW = new Set(["low", "informational", "info"]);
function hash(s: string): string { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return (h >>> 0).toString(16).padStart(8, "0"); }

export const r8: Checker = c => {
  const out: Violation[] = [];
  for (const f of c.feeds) {
    const atk = f.rows.filter(r => r.isAttack === true).length;
    const noise = f.rows.filter(r => r.isAttack === false).length;
    if (atk && noise < 2 * atk) out.push({ surface: f.surface, rule: "R8", rowId: f.id, detail: "noise below twice the attack rows", company: f.company, example: `${noise} noise vs ${atk} attack rows` });
    if (f.surface === "team") {
      const t = f.rows.filter(isTicket).length;
      if (t / f.rows.length > 0.1) out.push({ surface: f.surface, rule: "R8", rowId: f.id, detail: "tickets well above 8% of the feed", company: f.company, example: `${t} of ${f.rows.length} rows (${(100 * t / f.rows.length).toFixed(1)}%)` });
    }
  }
  // Per company: severity spread, ticket share and duplicates of the noise pool (live) / session (team).
  const byCompany = new Map<string, LogRow[]>();
  for (const r of c.rows) {
    if ((r.surface !== "live" && r.surface !== "team") || !r.company || r.meta?.mirrorOf) continue;
    const k = `${r.surface}|${r.company}`;
    (byCompany.get(k) ?? byCompany.set(k, []).get(k)!).push(r);
  }
  for (const [k, rows] of byCompany) {
    const [surface, company] = k.split("|") as [LogRow["surface"], string];
    const benign = rows.filter(r => r.isAttack === false), attack = rows.filter(r => r.isAttack === true);
    if (benign.length && !benign.some(r => HIGH.has(String(r.severity)))) out.push({ surface, rule: "R8", rowId: k.replace("|", ":"), detail: "no high-severity benign row", company, example: `${benign.length} benign rows` });
    if (attack.length && !attack.some(r => LOW.has(String(r.severity)))) out.push({ surface, rule: "R8", rowId: k.replace("|", ":"), detail: "no low-severity attack row", company, example: `${attack.length} attack rows` });
    if (surface === "live") {
      const pool = rows.filter(r => r.storyId?.endsWith(":pool"));
      const t = pool.filter(isTicket).length;
      if (pool.length && t / pool.length > 0.1) out.push({ surface, rule: "R8", rowId: `${company}:pool`, detail: "tickets above 8% of the noise pool", company, example: `${t} of ${pool.length}` });
    }
    const groups = new Map<string, LogRow[]>();
    for (const r of benign) {
      if (surface === "live" && !r.storyId?.endsWith(":pool")) continue;
      const key = `${r.source}/${r.eventType}|${contentKey(r)}`;
      (groups.get(key) ?? groups.set(key, []).get(key)!).push(r);
    }
    for (const [key, g] of groups) if (g.length >= 3) {
      out.push({ surface, rule: "R8", rowId: `${company}:${g[0].source}/${g[0].eventType}:${hash(key)}`, detail: "3 or more identical benign rows", company, example: `${g.length} copies: ${g.slice(0, 3).map(r => r.rowId).join(", ")}` });
    }
  }
  return out;
};
