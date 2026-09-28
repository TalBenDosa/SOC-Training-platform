import { describe, it, expect, vi } from "vitest";
vi.mock("server-only", () => ({}));
import { optionToken, decodeAnswer } from "./optionToken";

const q = { id: "q1", options: [{ value: "wrong_folder" }, { value: "right" }] };

describe("optionToken", () => {
  it("is deterministic, opaque and per slug/question", () => {
    const t = optionToken("s", "q1", "wrong_folder");
    expect(t).toBe(optionToken("s", "q1", "wrong_folder"));
    expect(t).not.toContain("wrong");
    expect(t).not.toBe(optionToken("s2", "q1", "wrong_folder"));
    expect(t).not.toBe(optionToken("s", "q2", "wrong_folder"));
  });
  it("decodes tokens and passes raw values through", () => {
    expect(decodeAnswer("s", q, optionToken("s", "q1", "right"))).toBe("right");
    expect(decodeAnswer("s", q, [optionToken("s", "q1", "right"), "wrong_folder"])).toEqual(["right", "wrong_folder"]);
    expect(decodeAnswer("s", q, "junk")).toBe("junk");
    expect(decodeAnswer("s", q, undefined)).toBeUndefined();
  });
});
