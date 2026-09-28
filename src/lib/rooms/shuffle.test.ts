import { describe, it, expect } from "vitest";
import {
  optionDisplayOrder, toOriginalIndex, toDisplayIndex, displayOptions,
  isPinnedOption, referencesOtherOptions, scrambleAwayFromAnswer, countFixedPoints,
  seededRandom, shuffleWithSeed, remapOptionLetters,
} from "./shuffle";

const OPTS = ["Alpha option", "Bravo option", "Charlie option", "Delta option"];

describe("optionDisplayOrder", () => {
  it("is a permutation of the original indices", () => {
    for (let s = 0; s < 50; s++) {
      const order = optionDisplayOrder(OPTS, `seed-${s}`);
      expect([...order].sort()).toEqual([0, 1, 2, 3]);
    }
  });

  it("is deterministic per seed", () => {
    expect(optionDisplayOrder(OPTS, "abc:task-1")).toEqual(optionDisplayOrder(OPTS, "abc:task-1"));
  });

  it("different seeds produce different orders (not stuck on one order)", () => {
    const seen = new Set<string>();
    for (let s = 0; s < 100; s++) seen.add(optionDisplayOrder(OPTS, `load-${s}:t`).join(","));
    expect(seen.size).toBeGreaterThan(12); // 24 possible orders for 4 options
  });

  it("round-trips display <-> original indices", () => {
    for (let s = 0; s < 30; s++) {
      const order = optionDisplayOrder(OPTS, `rt-${s}`);
      for (let orig = 0; orig < OPTS.length; orig++) {
        const d = toDisplayIndex(order, orig);
        expect(d).toBeGreaterThanOrEqual(0);
        expect(toOriginalIndex(order, d)).toBe(orig);
      }
      for (let d = 0; d < OPTS.length; d++) {
        expect(toDisplayIndex(order, toOriginalIndex(order, d))).toBe(d);
      }
    }
    expect(toDisplayIndex([0, 1], 5)).toBe(-1);
  });

  it("displayOptions labels match their original index", () => {
    const shown = displayOptions(OPTS, "x");
    shown.forEach((o, i) => {
      expect(o.displayIdx).toBe(i);
      expect(o.label).toBe(OPTS[o.srcIdx]);
    });
  });

  it("distributes the correct (original index 1) answer roughly uniformly across slots", () => {
    const counts = [0, 0, 0, 0];
    const N = 8000;
    for (let s = 0; s < N; s++) {
      const order = optionDisplayOrder(OPTS, `u${s}:task-7:q0`);
      counts[toDisplayIndex(order, 1)]++;
    }
    for (const c of counts) {
      expect(c / N).toBeGreaterThan(0.22);
      expect(c / N).toBeLessThan(0.28);
    }
  });
});

describe("pinning", () => {
  it("recognises position-relative options", () => {
    expect(isPinnedOption("All of the above")).toBe(true);
    expect(isPinnedOption("None of the above")).toBe(true);
    expect(isPinnedOption("Both of the above")).toBe(true);
    expect(isPinnedOption("Neither of these")).toBe(true);
    expect(isPinnedOption("all the above")).toBe(true);
    expect(isPinnedOption("Allow the connection")).toBe(false);
    expect(isPinnedOption("None — the host is clean")).toBe(false);
    expect(referencesOtherOptions("Both A and B")).toBe(true);
    expect(referencesOtherOptions("A and C")).toBe(true);
    expect(referencesOtherOptions("A, B and D")).toBe(true);
    expect(referencesOtherOptions("Options 1 and 2")).toBe(true);
    expect(referencesOtherOptions("Block C2 and alert")).toBe(false);
    expect(referencesOtherOptions("Enable MFA and rotate keys")).toBe(false);
  });

  it("keeps 'All of the above' in its authored slot and shuffles the rest", () => {
    const opts = ["One", "Two", "Three", "All of the above"];
    const orders = new Set<string>();
    for (let s = 0; s < 60; s++) {
      const order = optionDisplayOrder(opts, `p${s}`);
      expect(order[3]).toBe(3);
      orders.add(order.join(","));
    }
    expect(orders.size).toBeGreaterThan(1);
  });

  it("pins a middle 'None of the above' too", () => {
    const opts = ["One", "None of the above", "Three", "Four"];
    for (let s = 0; s < 40; s++) expect(optionDisplayOrder(opts, `m${s}`)[1]).toBe(1);
  });

  it("does not shuffle a question whose option names other options by letter", () => {
    const opts = ["Phishing", "Vishing", "Smishing", "Both A and B"];
    for (let s = 0; s < 20; s++) expect(optionDisplayOrder(opts, `l${s}`)).toEqual([0, 1, 2, 3]);
  });

  it("leaves single-option and all-pinned lists alone", () => {
    expect(optionDisplayOrder(["Only"], "s")).toEqual([0]);
    expect(optionDisplayOrder(["Yes", "All of the above"], "s")).toEqual([0, 1]);
  });
});

describe("shuffleWithSeed", () => {
  it("is deterministic and a permutation", () => {
    const a = shuffleWithSeed(["tp", "fp", "esc", "info"], "k");
    expect(a).toEqual(shuffleWithSeed(["tp", "fp", "esc", "info"], "k"));
    expect([...a].sort()).toEqual(["esc", "fp", "info", "tp"]);
  });
});

describe("scrambleAwayFromAnswer", () => {
  const answer = ["a", "b", "c", "d", "e"];
  const id = (x: string) => x;

  it("never returns the answer order", () => {
    for (let s = 0; s < 200; s++) {
      const out = scrambleAwayFromAnswer(answer, answer, id, seededRandom(s));
      expect(out.join()).not.toBe(answer.join());
      expect([...out].sort()).toEqual(answer);
      expect(countFixedPoints(out, answer)).toBeLessThanOrEqual(2);
    }
  });

  it("keeps an already-scrambled order untouched", () => {
    const scrambled = ["c", "a", "e", "b", "d"];
    expect(scrambleAwayFromAnswer(scrambled, answer, id)).toEqual(scrambled);
  });

  it("falls back to a rotation when randomness is degenerate", () => {
    const out = scrambleAwayFromAnswer(answer, answer, id, () => 0.999999);
    expect(countFixedPoints(out, answer)).toBeLessThanOrEqual(2);
    expect(out.join()).not.toBe(answer.join());
  });

  it("works on keyed objects and 2-item boards", () => {
    const items = [{ id: "x" }, { id: "y" }];
    const out = scrambleAwayFromAnswer(items, ["x", "y"], i => i.id, seededRandom(1));
    expect(out.map(i => i.id)).toEqual(["y", "x"]);
  });
});

describe("remapOptionLetters", () => {
  // order[display] = original: authored a,b,c,d shown as c,a,d,b
  const order = [2, 0, 3, 1];
  it("renames letter references to the letters the learner saw", () => {
    expect(remapOptionLetters("Option c is wrong. Option a invents a range.", order))
      .toBe("Option a is wrong. Option b invents a range.");
    expect(remapOptionLetters("Options A and D both fail; (b) is the trap. Answer C.", order))
      .toBe("Options B and C both fail; (d) is the trap. Answer A.");
  });
  it("leaves prose, out-of-range letters and identity order alone", () => {
    expect(remapOptionLetters("Other options and alerts matter.", order)).toBe("Other options and alerts matter.");
    expect(remapOptionLetters("Option f is not an option here.", order)).toBe("Option f is not an option here.");
    expect(remapOptionLetters("Option c is wrong.", [0, 1, 2, 3])).toBe("Option c is wrong.");
  });
});
