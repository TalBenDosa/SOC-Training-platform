/**
 * The EDR console's verdict rule, shared by the console (instant feedback) and the
 * server (POST /api/me/edr-results re-grades before storing, so a stored result can
 * never claim "correct" for a wrong call). Pure and isomorphic.
 *
 * A student who flags ANY process the console itself confirms malicious (its hash
 * resolves malicious under "Look up hash", the same hashIntel call) has correctly
 * identified a malicious process, even when a different process is the designated
 * payload the debrief highlights. Benign resolution (-1) is correct only when the case
 * truly has no payload; in a benign case, flagging any process is wrong.
 */
import type { EdrInvestigation } from "./investigations";
import { hashIntel } from "./iocIntel";

export function gradeEdrChoice(inv: EdrInvestigation, choice: number /* pid, or -1 for benign */): boolean {
  if (choice === -1) return inv.answer.pid === -1;
  if (inv.answer.pid < 0) return false;
  if (choice === inv.answer.pid) return true;
  const p = inv.processes.find(x => x.pid === choice);
  if (!p?.sha256) return false;
  const flagged = p.verdict === "malicious" || p.verdict === "suspicious" || inv.detections.some(d => d.pid === p.pid);
  return hashIntel(p.sha256, { truth: inv.iocTruth, process: { signed: p.signed, flagged } }).verdict === "malicious";
}
