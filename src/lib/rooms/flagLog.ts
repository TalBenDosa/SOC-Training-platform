/**
 * Which log a flag task shows next to its question. A flag usually asks about a log the student
 * read earlier, and is often not right after it (a verdict scenario or a reading can sit
 * between), so "the nearest log" can be the WRONG one: the student then sees a log that does
 * not contain the answer (2026-10-09 report: "Machine hostname is missing" in
 * firewall-log-analysis, where the flag asked about the blocked-C2 log but the later verdict
 * log, with a look-alike hostname, was shown).
 *
 * Resolution order:
 *  1. `event` pinned on the flag (or `null` for a knowledge flag with no log);
 *  2. `logTask`: the id of the log task the flag is about;
 *  3. a log task whose heading the prompt quotes ("Go back to the 'Analysing ...' log");
 *  4. "Log Analysis N" in the prompt: the Nth log_analysis task;
 *  5. the nearest preceding log (a log_analysis when the prompt says "log analysis").
 */
interface LogLike { type: string; id?: string; heading?: string; prompt?: string; event?: unknown; logTask?: string }

export function resolveFlagLog<E>(tasks: LogLike[], index: number): E | undefined {
  const cur = tasks[index];
  if (!cur || cur.type !== "flag") return undefined;
  if (cur.event !== undefined) return (cur.event ?? undefined) as E | undefined;
  const isLog = (t: LogLike) => t.type === "log_analysis" || t.type === "analyst_choice";
  if (cur.logTask) {
    const t = tasks.find(x => x.id === cur.logTask && isLog(x));
    if (t) return t.event as E;
  }
  const prompt = cur.prompt ?? "";
  const lower = prompt.toLowerCase();
  const named = tasks.slice(0, index).filter(t => isLog(t) && !!t.heading && t.heading.length >= 8 && lower.includes(t.heading.toLowerCase())).pop();
  if (named) return named.event as E;
  const m = prompt.match(/log analysis\s+(\d+)/i);
  if (m) {
    let n = 0;
    for (const t of tasks) if (t.type === "log_analysis" && ++n === Number(m[1])) return t.event as E;
  }
  const wantsLogAnalysis = /log[-\s]?analysis/i.test(prompt);
  let nearest: LogLike | undefined, nearestLa: LogLike | undefined;
  for (let i = index - 1; i >= 0; i--) {
    const t = tasks[i];
    if (!isLog(t)) continue;
    nearest ??= t;
    if (t.type === "log_analysis") { nearestLa = t; break; }
  }
  return (wantsLogAnalysis && nearestLa ? nearestLa : nearest)?.event as E | undefined;
}
