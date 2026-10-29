import { describe, it, expect } from "vitest";
import { EDR_INVESTIGATIONS } from "./investigations";
import { sampleFromPath, peInfo, stringsOutput, flossOutput, capaOutput, candidateIocs } from "./staticLab";

const inv = EDR_INVESTIGATIONS.find(i => i.id === "phishing-beacon")!;
const DLL = "C:\\Users\\r.bakker\\AppData\\Roaming\\svc\\update.dll";
const s = sampleFromPath(inv, DLL)!;

describe("Static Analysis Lab: consistency with the case", () => {
  it("resolves the collected DLL with the EDR's own hash and signature", () => {
    expect(s).toBeTruthy();
    expect(s.isPe && s.isDll).toBe(true);
    expect(s.sha256).toBe(inv.processes.find(p => p.pid === 6388)!.sha256);
    expect(s.signed).toBe(false);
    expect(s.exports).toContain("Start");          // from `rundll32 …update.dll,Start`
  });

  it("file size equals the logged download, and the sections add up to it", () => {
    const dl = Math.max(...inv.processes.find(p => p.pid === 6240)!.network!.map(c => c.bytes ?? 0));
    expect(s.sizeBytes).toBe(dl);
    const rows = [...peInfo(s).matchAll(/^\s{2}\.\w+\s+0x([0-9a-f]{8})\s+([\d,]+)/gm)];
    expect(rows).toHaveLength(4);
    const raws = rows.map(r => Number(r[2].replace(/,/g, "")));
    expect(0x400 + raws.reduce((a, b) => a + b, 0)).toBe(s.sizeBytes);
    expect(raws.every(r => r % 0x200 === 0)).toBe(true);          // FileAlignment
    const vas = rows.map(r => parseInt(r[1], 16));
    expect(vas[0]).toBe(0x1000);
    expect(vas.every(v => v % 0x1000 === 0)).toBe(true);          // SectionAlignment
  });

  it("strings prints each line once and nothing shorter than -n 6", () => {
    const lines = stringsOutput(s).split("\n");
    expect(new Set(lines).size).toBe(lines.length);
    expect(lines.every(l => l.length >= 6)).toBe(true);
    expect(lines).toContain("cdn-msupdate.info");                  // the real C2 is visible
    expect(lines.some(l => /crl\.microsoft\.com/.test(l))).toBe(true); // alongside PKI noise
  });

  it("FLOSS stack strings come only from what the case shows the file touching", () => {
    const out = flossOutput(s);
    const stack = out.split("stack strings")[1].split("decoded strings")[0];
    expect(stack).toMatch(/Login Data/);
    expect(stack).not.toMatch(/cmd\.exe|pipe|Global\\/);
    const decoded = out.split("decoded strings")[1].trim().split("\n").slice(1);
    expect(new Set(decoded).size).toBe(decoded.length);
    expect(decoded).toContain("sleep 30000");                      // 09:42:04 -> 09:42:34
  });

  it("capa maps observed behaviour to ATT&CK and says it is not a verdict", () => {
    const out = capaOutput(s);
    expect(out).toMatch(/T1071\.001/);
    expect(out).toMatch(/T1555\.003/);
    expect(out).toMatch(/not whether it is malicious/);
  });

  it("pivot candidates are the C2 domain and IP, once each", () => {
    expect(candidateIocs(s)).toEqual([{ value: "cdn-msupdate.info", type: "domain" }, { value: "45.137.22.19", type: "ip" }]);
  });

  it("a path the host never saw does not resolve", () => {
    expect(sampleFromPath(inv, "C:\\nope\\missing.dll")).toBeNull();
  });
});
