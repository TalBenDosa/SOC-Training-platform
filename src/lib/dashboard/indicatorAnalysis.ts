/**
 * Indicator citation / fabrication analysis for the incident-report grader.
 *
 * Pure (no server-only deps) so it can be unit-tested directly — the grading
 * route (src/app/api/dashboard/incident-report/route.ts) imports it. Keeping it
 * here also lets the fabrication rules be regression-tested in isolation, which
 * matters because a false "fabricated" flag is a serious trust-breaker: it caps a
 * correct report's Evidence score and tells a trainee they invented data they
 * actually cited correctly.
 */

/**
 * Compare the indicators the student CLAIMED in their write-up against the real
 * indicators from the attack. Returns which real ones they correctly cited and
 * which claimed values are fabricated (invented — not in the logs at all).
 *
 * A value is REAL if it matches a discrete ground-truth indicator OR appears
 * anywhere in the serialized evidence (raw log blocks included) — the
 * evidence-substring arm is what stops a genuinely-observable value (an MD5/SHA1,
 * a private host IP, a vendor-keyed raw field the discrete list doesn't enumerate)
 * from being branded "fabricated".
 */
export function analyseIndicators(summary: string, real: string[], evidenceText = ""): { cited: string[]; fabricated: string[] } {
  const t = summary.toLowerCase();
  const realLower = real.map(r => r.toLowerCase());
  const evidence = evidenceText.toLowerCase();
  const isReal = (v: string) => {
    const lv = v.toLowerCase();
    return (evidence.length > 0 && evidence.includes(lv)) ||
      realLower.some(r => r === lv || r.includes(lv) || lv.includes(r));
  };

  // Which real indicators did they quote?
  const cited = real.filter(r => {
    const lr = r.toLowerCase();
    return t.includes(lr) || t.includes(lr.split("@")[0]); // full value or username part
  });

  // Extract indicator-shaped claims from the student's text
  const claimed = new Set<string>();
  for (const m of summary.matchAll(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g))  claimed.add(m[0]); // IPv4
  for (const m of summary.matchAll(/\b[\w.+-]+@[\w.-]+\.\w{2,}\b/g)) claimed.add(m[0]); // email
  for (const m of summary.matchAll(/\b[0-9a-f]{32,64}\b/gi))         claimed.add(m[0]); // hash
  // Host claims — ONLY an explicit "host: X" / "hostname = X" (any token), or "host X"
  // where X is HOST-SHAPED (contains a digit, hyphen or dot — e.g. WS-FIN-3041, DC01,
  // srv-app.corp). An earlier pattern allowed an OPTIONAL separator, so ordinary prose
  // — "isolate the host and reset the account", "the host was compromised" — extracted
  // the next English word ("and", "was") as a claimed hostname. Not being in the logs,
  // it was branded FABRICATED, which caps Evidence to 5 and drops a correct report to
  // ~60 with a "fabricated evidence" verdict — the exact trust-breaker a trainee
  // reported after correctly citing a real hash. English words are never host-shaped,
  // so they no longer trip the check; a genuinely invented "host: koko" still does.
  for (const m of summary.matchAll(/\bhost(?:name)?\s*[:=]\s*([a-z0-9][\w.-]*)/gi))       claimed.add(m[1]);
  for (const m of summary.matchAll(/\bhost(?:name)?\s+([a-z0-9][\w.-]*[-.\d][\w.-]*)/gi)) claimed.add(m[1]);

  // length >= 4 mirrors the scenario grader's precision guard — a 2-3 char token is
  // noise, never a real indicator, and must never be reported as "fabricated".
  const fabricated = [...claimed].filter(v => v.length >= 4 && !isReal(v));
  return { cited, fabricated };
}
