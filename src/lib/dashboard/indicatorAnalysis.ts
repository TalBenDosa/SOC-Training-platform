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
/**
 * Everyday Windows/browser/office binaries: they appear in almost every attack
 * chain as the PARENT of something, so naming one proves nothing about the
 * incident. They never count as a cited indicator (QA-DASH-3).
 */
export const BENIGN_PROCESS_NAMES = new Set([
  "explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "outlook.exe",
  "winword.exe", "excel.exe", "powerpnt.exe", "teams.exe", "svchost.exe", "services.exe",
  "lsass.exe", "winlogon.exe", "csrss.exe", "smss.exe", "wininit.exe", "system", "conhost.exe",
  "runtimebroker.exe", "taskhostw.exe", "dllhost.exe", "sihost.exe", "searchindexer.exe",
]);

/**
 * Tokens of a text: whole values, never substrings. "10.0.0.1" must not match
 * inside "10.0.0.15", and a username must not match inside another word
 * (QA-DASH-3: substring matching made invented values count as real).
 */
export function indicatorTokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of text.toLowerCase().split(/[\s"'`,;()[\]{}<>|=]+/)) {
    const tok = raw.replace(/^[.:!?]+|[.:!?]+$/g, "");
    if (!tok) continue;
    out.add(tok);
    // a path or a DOMAIN\user also yields its last segment (the file / user name)
    const last = tok.split(/[\\/]/).pop();
    if (last && last !== tok) out.add(last);
    // an email also yields its user part
    const at = tok.indexOf("@");
    if (at > 0) out.add(tok.slice(0, at));
  }
  return out;
}

export function analyseIndicators(summary: string, real: string[], evidenceText = ""): { cited: string[]; fabricated: string[] } {
  const said = indicatorTokens(summary);
  const evidence = indicatorTokens(evidenceText);
  const realLower = new Set(real.map(r => r.toLowerCase()));
  const isReal = (v: string) => {
    const lv = v.toLowerCase();
    return evidence.has(lv) || realLower.has(lv);
  };

  // Which real indicators did they quote? Whole value, or the user part of an
  // email (3+ chars). Everyday process names never count.
  const cited = real.filter(r => {
    const lr = r.toLowerCase();
    if (BENIGN_PROCESS_NAMES.has(lr)) return false;
    if (said.has(lr)) return true;
    const user = lr.includes("@") ? lr.split("@")[0] : "";
    return user.length >= 3 && said.has(user);
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
