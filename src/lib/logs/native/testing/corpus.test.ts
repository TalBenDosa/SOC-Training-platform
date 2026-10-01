import { describe, it, expect } from "vitest";
import { corpus, corpusFor, cardSamples } from "./corpus";
describe("corpus", () => {
  it("loads every authored event and the card samples", () => {
    expect(corpus().length).toBeGreaterThan(1300);
    expect(corpusFor(["cloudtrail"]).length).toBeGreaterThan(50);
    expect(cardSamples("cloud-aws-cloudtrail.md").length).toBeGreaterThan(10);
  });
});
