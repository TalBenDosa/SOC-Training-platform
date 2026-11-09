/**
 * R7 A story can be proven from its evidence.
 *  a. Every XDR alert links the events behind it.
 *  b. A password spray (T1110.003) shows at least 10 failed sign-ins over at least 8 accounts within
 *     10 minutes of feed time; a brute force or stuffing (T1110.001 / .004) at least 10 failures.
 *     Counted per story (live story, scenario, team incident) on the rows the learner sees. A record
 *     that counts failed guesses itself (ATTEMPT_COUNT_FIELDS: a GraphQL service's UNAUTHENTICATED
 *     errors for one batched request) adds its count: one row, many proven attempts. Accounts are
 *     not countable that way, so a spray still needs its failures as rows.
 * Not mechanical (README): "a twist happens after the attacker reached what it needs" and "a benign
 * look-alike carries the evidence that disproves it".
 */
import type { Checker, LogRow, Violation } from "../types";

const FAIL = new Set(["auth_failure", "ssh_failed", "vpn_failed", "db_failed", "mfa_denied"]);

/**
 * Fields in which a record itself counts failed authentication attempts. Each one is a real field of
 * the record it is read from, and counts only failures, never requests:
 *  - graphql.errors.UNAUTHENTICATED: the origin GraphQL service's request log (pino-http with the
 *    service's customProps) counts the UNAUTHENTICATED errors of one response, one per failed SignIn
 *    alias of a batched document (Apollo Server error code UNAUTHENTICATED).
 */
export const ATTEMPT_COUNT_FIELDS = ["graphql.errors.UNAUTHENTICATED"];

/** Failed attempts a row proves: its own count field when it has one (an integer >= 1), else none. */
export function countedAttempts(r: LogRow): number {
  const rec = (typeof r.raw === "object" ? r.raw : undefined) ?? (r.ev?.raw as Record<string, unknown> | undefined) ?? {};
  let n = 0;
  for (const k of ATTEMPT_COUNT_FIELDS) {
    const v = Number(rec[k]);
    if (Number.isInteger(v) && v > 0) n += v;
  }
  return n;
}

function account(r: LogRow): string {
  const ev = r.ev!;
  const raw = (ev.raw ?? {}) as Record<string, unknown>;
  const a = ev.user_email ?? ev.user?.email ?? raw["winlog.event_data.TargetUserName"] ?? raw.TargetUserName ?? raw["user.name"] ?? raw["okta.actor.alternate_id"] ?? raw["vsphere.event.userName"] ?? "";
  return String(a).toLowerCase().split("@")[0].split("\\").pop() ?? "";
}

/** Some window of `minutes` holds at least 10 failures over at least 8 accounts. */
function burstWithin(fails: LogRow[], minutes: number): boolean {
  const s = fails.filter(r => Number.isFinite(r.time)).sort((a, b) => a.time! - b.time!);
  for (let i = 0, j = 0; i < s.length; i++) {
    while (s[i].time! - s[j].time! > minutes * 60_000) j++;
    const win = s.slice(j, i + 1);
    if (win.length >= 10 && new Set(win.map(account).filter(Boolean)).size >= 8) return true;
  }
  return false;
}

export const r7: Checker = c => {
  const out: Violation[] = [];
  for (const r of c.rows) {
    if (r.surface === "xdr" && r.meta?.alert && !(r.meta.eventIds as string[] | undefined)?.length) {
      out.push({ surface: "xdr", rule: "R7", rowId: r.rowId, detail: "alert with no linked events", company: r.company, example: r.rowId });
    }
  }
  const stories = new Map<string, LogRow[]>();
  for (const r of c.rows) {
    if (!r.ev || r.meta?.mirrorOf || (r.surface !== "live" && r.surface !== "scenario" && r.surface !== "team")) continue;
    if (r.surface === "live" && r.storyId?.endsWith(":pool")) continue;
    const inc = r.surface === "team" ? r.meta?.incident : undefined;
    if (r.surface === "team" && !inc) continue;
    const k = `${r.surface}|${r.storyId}${inc ? `|${String(inc)}` : ""}`;
    (stories.get(k) ?? stories.set(k, []).get(k)!).push(r);
  }
  for (const [k, rows] of stories) {
    const techs = new Set(rows.map(r => r.ev!.mitre_technique).filter(Boolean));
    const spray = techs.has("T1110.003");
    const brute = techs.has("T1110.001") || techs.has("T1110.004") || techs.has("T1110");
    if (!spray && !brute) continue;
    const fails = rows.filter(r => FAIL.has(r.ev!.event_type) || r.ev!.network?.status === 401 || r.ev!.network?.status === 403);
    // Guesses a record counts itself (a batched GraphQL sign-in): attempts the learner can read, one row.
    const counted = rows.filter(r => !fails.includes(r)).reduce((n, r) => n + countedAttempts(r), 0);
    const accounts = new Set(fails.map(account).filter(Boolean));
    const times = fails.map(r => r.time ?? NaN).filter(Number.isFinite);
    const span = times.length ? (Math.max(...times) - Math.min(...times)) / 60_000 : 0;
    const [surface, ...rest] = k.split("|");
    const rowId = rest.join("|");
    const ex = `${fails.length} failures${counted ? ` + ${counted} counted in records` : ""}, ${accounts.size} accounts, over ${span.toFixed(1)} min`;
    if (spray && (fails.length < 10 || accounts.size < 8)) out.push({ surface: surface as LogRow["surface"], rule: "R7", rowId, detail: "spray not provable: fewer than 10 failures over 8 accounts", company: rows[0].company, example: ex });
    // The spray is proven by its burst: some 10-minute window holds 10 failures over 8 accounts. Later
    // failures of the same story (the victim's own MFA denials after the takeover) do not unprove it.
    else if (spray && span > 10 && !burstWithin(fails, 10)) out.push({ surface: surface as LogRow["surface"], rule: "R7", rowId, detail: "spray failures spread over more than 10 minutes", company: rows[0].company, example: ex });
    else if (!spray && brute && fails.length + counted < 10) out.push({ surface: surface as LogRow["surface"], rule: "R7", rowId, detail: "brute force not provable: fewer than 10 failures", company: rows[0].company, example: ex });
  }
  return out;
};
