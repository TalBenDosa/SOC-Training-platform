// The call on a host is "malicious, act" or "benign, close" (Tal, 2026-11-23): containing a host in a
// malicious case is right whatever process is selected, and so is flagging any process of the chain.
import { describe, it, expect } from "vitest";
import { EDR_INVESTIGATIONS } from "./investigations";
import { CONTAIN_CHOICE, gradeEdrChoice, gradeEdrDecision } from "./grade";

const malicious = EDR_INVESTIGATIONS.filter(i => i.answer.pid >= 0);
const benign = EDR_INVESTIGATIONS.filter(i => i.answer.pid < 0);

describe("EDR verdict rule", () => {
  it("has both kinds of practice case", () => {
    expect(malicious.length).toBeGreaterThan(0);
    expect(benign.length).toBeGreaterThan(0);
  });

  it("containing the host is right in every malicious case and wrong in every benign one", () => {
    for (const inv of malicious) expect(gradeEdrDecision(inv, CONTAIN_CHOICE), inv.id).toEqual({ correct: true, exact: false });
    for (const inv of benign) expect(gradeEdrChoice(inv, CONTAIN_CHOICE), inv.id).toBe(false);
  });

  it("the payload is exact; any other process of the chain is right but not exact", () => {
    for (const inv of malicious) {
      expect(gradeEdrDecision(inv, inv.answer.pid), inv.id).toEqual({ correct: true, exact: true });
      for (const p of inv.processes.filter(x => x.pid !== inv.answer.pid && (x.verdict === "suspicious" || inv.detections.some(d => d.pid === x.pid)))) {
        expect(gradeEdrDecision(inv, p.pid), `${inv.id} ${p.name}`).toEqual({ correct: true, exact: false });
      }
    }
  });

  it("a benign process outside the chain is wrong; benign resolution only fits a benign case", () => {
    for (const inv of malicious) {
      const clean = inv.processes.find(p => p.verdict === "benign" && !p.sha256 && !inv.detections.some(d => d.pid === p.pid));
      if (clean) expect(gradeEdrChoice(inv, clean.pid), `${inv.id} ${clean.name}`).toBe(false);
      expect(gradeEdrChoice(inv, -1), inv.id).toBe(false);
    }
    for (const inv of benign) {
      expect(gradeEdrDecision(inv, -1), inv.id).toEqual({ correct: true, exact: true });
      for (const p of inv.processes) expect(gradeEdrChoice(inv, p.pid), `${inv.id} ${p.name}`).toBe(false);
    }
  });
});
