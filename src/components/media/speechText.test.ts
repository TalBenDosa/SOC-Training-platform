import { describe, it, expect } from "vitest";
import { toSpeechText, chunkForSpeech } from "./speechText";

describe("toSpeechText", () => {
  it("replaces code blocks with a cue and strips formatting", () => {
    const md = "## Kerberos\n\nThe **KDC** issues a `TGT`.\n\n```kql\nSecurityEvent | where EventID == 4769\n```\n\n- first\n- second";
    const out = toSpeechText(md);
    expect(out).toContain("Kerberos.");
    expect(out).toContain("The KDC issues a TGT.");
    expect(out).toContain("Code example shown on screen");
    expect(out).not.toContain("SecurityEvent");
    expect(out).not.toMatch(/[*`#]/);
    expect(out).toContain("first");
  });

  it("reads tables row by row and keeps link text", () => {
    const md = "| Port | Service |\n|---|---|\n| 22 | SSH |\n\nSee [MITRE](https://attack.mitre.org).";
    const out = toSpeechText(md);
    expect(out).toContain("Port, Service.");
    expect(out).toContain("22, SSH.");
    expect(out).toContain("See MITRE.");
    expect(out).not.toContain("---");
    expect(out).not.toContain("https://");
  });

  it("handles empty input", () => {
    expect(toSpeechText("")).toBe("");
  });
});

describe("chunkForSpeech", () => {
  it("keeps chunks under the limit without losing words", () => {
    const text = Array.from({ length: 40 }, (_, i) => `Sentence number ${i} is here.`).join(" ");
    const chunks = chunkForSpeech(text, 120);
    expect(chunks.length).toBeGreaterThan(1);
    for (const c of chunks) expect(c.length).toBeLessThanOrEqual(120);
    expect(chunks.join(" ").split(/\s+/).length).toBe(text.split(/\s+/).length);
  });

  it("hard-wraps a single overlong sentence", () => {
    const long = "word ".repeat(200).trim();
    for (const c of chunkForSpeech(long, 100)) expect(c.length).toBeLessThanOrEqual(100);
  });
});
