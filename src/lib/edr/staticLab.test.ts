import { describe, it, expect } from "vitest";
import { EDR_INVESTIGATIONS } from "./investigations";
import { sampleFromPath, peInfo, stringsOutput, flossOutput, capaOutput, candidateIocs, classifyIndicator, labLookup, sampleMd5 } from "./staticLab";
import { hashIntel } from "./iocIntel";

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

describe("Static Analysis Lab: verifying what was found", () => {
  it("the DLL hash gets the same verdict as the process panel's Look up hash", () => {
    const p = inv.processes.find(x => x.pid === 6388)!;
    const panel = hashIntel(p.sha256!, { truth: inv.iocTruth, process: { signed: p.signed, flagged: true } });
    const lab = labLookup(inv, s, "hash", s.sha256);
    expect(lab.type).toBe("hash");
    if (lab.type !== "hash") return;
    expect(lab.data.verdict).toBe(panel.verdict);
    expect(lab.data.detected).toBe(panel.detected);
    expect(lab.data.malwareFamily).toBe(panel.malwareFamily);
    expect(lab.data.fileType).toBe("Win32 DLL");             // agrees with File info
  });

  it("the C2 the flagged process beaconed to reads malicious; PKI noise reads clean", () => {
    const dom = labLookup(inv, s, "domain", "cdn-msupdate.info");
    const ip = labLookup(inv, s, "ip", "45.137.22.19");
    const crl = labLookup(inv, s, "domain", "crl.microsoft.com");
    expect(dom.data.verdict).toBe("malicious");
    expect(ip.data.verdict).toBe("malicious");
    expect(crl.data.verdict).toBe("clean");
  });

  it("classifies pasted values: hash, the shown MD5, IP, URL to host, and rejects API names", () => {
    expect(classifyIndicator(s.sha256)).toEqual({ type: "hash", value: s.sha256 });
    expect(classifyIndicator(sampleMd5(s), s)).toEqual({ type: "hash", value: s.sha256 });
    expect(classifyIndicator("45.137.22.19")).toEqual({ type: "ip", value: "45.137.22.19" });
    expect(classifyIndicator("https://cdn-msupdate.info/5e544f")).toEqual({ type: "domain", value: "cdn-msupdate.info" });
    expect(classifyIndicator("GetProcAddress")).toBeNull();
    expect(classifyIndicator("   ")).toBeNull();
  });
});
