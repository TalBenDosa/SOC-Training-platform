import { describe, it, expect } from "vitest";
import {
  displayedOptions, optionDisplayOrderFor, remapExplanation, buildOptionTokens, decodeAnswers, optionLetter,
} from "./quizDisplay";
import { buildMultiHostIntrusionScenario } from "@/lib/sim/scenario-packs/multiHostIntrusion";

const b = buildMultiHostIntrusionScenario();

describe("letter remap wiring (#15)", () => {
  it("order[display] = authored index and covers every option", () => {
    for (const q of b.questions) {
      const order = optionDisplayOrderFor(q);
      expect([...order].sort()).toEqual(q.options!.map((_, i) => i));
      const shown = displayedOptions(q);
      order.forEach((orig, disp) => expect(shown[disp].value).toBe(q.options![orig].value));
    }
  });

  it("multi-host Q1/Q2/Q4: every '(x)' in the remapped explanation names the option the author meant", () => {
    for (const qid of ["q1", "q2", "q4"]) {
      const q = b.questions.find(x => x.id === qid)!;
      const authoredRefs = [...q.explanation.matchAll(/\(([a-d])\)/g)].map(m => m[1]);
      expect(authoredRefs.length, qid).toBeGreaterThan(0);
      const remapped = remapExplanation(q.explanation, q)!;
      const shownRefs = [...remapped.matchAll(/\(([a-d])\)/g)].map(m => m[1]);
      expect(shownRefs.length).toBe(authoredRefs.length);
      const shown = displayedOptions(q);
      authoredRefs.forEach((a, i) => {
        const authoredOpt = q.options![a.charCodeAt(0) - 97];
        const displayedOpt = shown[shownRefs[i].charCodeAt(0) - 97];
        expect(displayedOpt.value, `${qid} (${a})`).toBe(authoredOpt.value);
      });
    }
  });

  it("passes null / unknown question through", () => {
    expect(remapExplanation(null, b.questions[0])).toBeNull();
    expect(remapExplanation("see (b)", undefined)).toBe("see (b)");
    expect(optionLetter(0)).toBe("A");
    expect(optionLetter(3)).toBe("D");
  });
});

describe("opaque option tokens (#4)", () => {
  it("tokens reveal nothing and round-trip to the real ids", () => {
    const map = buildOptionTokens(b.questions);
    for (const q of b.questions) {
      const to = map.toToken.get(q.id)!;
      for (const o of q.options!) {
        const t = to.get(o.value)!;
        expect(t).toMatch(/^o_[a-z0-9]{10}$/);
        expect(t).not.toContain(o.value);
      }
      expect(new Set(to.values()).size).toBe(q.options!.length);
    }
    const q1 = b.questions[0];
    const tok = map.toToken.get(q1.id)!.get(q1.options![2].value)!;
    expect(decodeAnswers({ [q1.id]: tok }, map)).toEqual({ [q1.id]: q1.options![2].value });
  });
  it("differs per load", () => {
    const a = buildOptionTokens(b.questions);
    const c = buildOptionTokens(b.questions);
    const v = b.questions[0].options![0].value;
    expect(a.toToken.get(b.questions[0].id)!.get(v)).not.toBe(c.toToken.get(b.questions[0].id)!.get(v));
  });
  it("decodes multi answers and drops unknown tokens", () => {
    const qs = [{ id: "m", options: [{ value: "x", label: "X" }, { value: "y", label: "Y" }] }];
    const map = buildOptionTokens(qs);
    const tx = map.toToken.get("m")!.get("x")!;
    const ty = map.toToken.get("m")!.get("y")!;
    expect(decodeAnswers({ m: [tx, "bogus", ty] }, map)).toEqual({ m: ["x", "y"] });
    expect(decodeAnswers({ m: "bogus", nope: "z" }, map)).toEqual({});
  });
});
