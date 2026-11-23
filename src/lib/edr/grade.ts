/**
 * The EDR console's verdict rule, shared by the console (instant feedback) and the
 * server (POST /api/me/edr-results re-grades before storing, so a stored result can
 * never claim "correct" for a wrong call). Pure and isomorphic.
 *
 * The call an analyst makes on a host is "malicious, act" or "benign, close" (Tal, 2026-11-23:
 * "the incident is clearly malicious; containing it must not depend on which process I had
 * selected"). So in a malicious case:
 *   - CONTAINING the host (Isolate host, RTR `contain`) is the right call, whatever is selected;
 *   - flagging any process of the attack chain is the right call: a process the sensor raised a
 *     behavior on, a process the case marks malicious / suspicious, or one whose hash resolves
 *     malicious under "Look up hash". The debrief still names the payload (`exact` tells the
 *     console whether the learner pinned it).
 * In a benign case, resolving as benign (-1) is the only right call: flagging a process or
 * isolating the host is over-reaction.
 */
import type { EdrInvestigation } from "./investigations";
import { hashIntel } from "./iocIntel";

/** The choice code for "contain the host" (pids are positive, -1 is "benign"). */
export const CONTAIN_CHOICE = -2;

export interface EdrGrade { correct: boolean; /** The learner pinned the payload itself. */ exact: boolean }

export function gradeEdrDecision(inv: EdrInvestigation, choice: number /* pid, -1 benign, -2 contain */): EdrGrade {
  const malicious = inv.answer.pid >= 0;
  if (choice === -1) return { correct: !malicious, exact: !malicious };
  if (!malicious) return { correct: false, exact: false };
  if (choice === CONTAIN_CHOICE) return { correct: true, exact: false };
  if (choice === inv.answer.pid) return { correct: true, exact: true };
  const p = inv.processes.find(x => x.pid === choice);
  if (!p) return { correct: false, exact: false };
  const inChain = p.verdict === "malicious" || p.verdict === "suspicious" || inv.detections.some(d => d.pid === p.pid);
  if (inChain) return { correct: true, exact: false };
  const bad = !!p.sha256 && hashIntel(p.sha256, { truth: inv.iocTruth, process: { signed: p.signed, flagged: false } }).verdict === "malicious";
  return { correct: bad, exact: false };
}

export function gradeEdrChoice(inv: EdrInvestigation, choice: number /* pid, -1 benign, -2 contain */): boolean {
  return gradeEdrDecision(inv, choice).correct;
}
