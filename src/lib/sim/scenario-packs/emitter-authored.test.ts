import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { buildClipboardClipperScenario } from "./clipboardClipper";
import { buildTrojanizedInstallerKeyloggerScenario } from "./trojanizedInstallerKeylogger";
import { buildSeoPoisonedInstallerScenario } from "./seoPoisonedInstaller";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";

// Packs that have been fully converted to the vendor emitters. Each MUST stay 100%
// emitter-authored — no hand-typed `raw: { … }` block may creep back in, because that
// is exactly the drift the emitter layer exists to prevent (a hand-typed field can be
// wrong; an emitter-rendered one is registry-correct by construction).
const FULLY_EMITTER_AUTHORED = [
  "clipboardClipper.ts", "trojanizedInstallerKeylogger.ts", "seoPoisonedInstaller.ts",
  "fakeBrowserUpdate.ts", "clickFixFakeCaptcha.ts",
];

describe("emitter-authored scenario packs", () => {
  it.each(FULLY_EMITTER_AUTHORED)("%s contains no hand-authored raw blocks", (file) => {
    const src = fs.readFileSync(path.resolve("src/lib/sim/scenario-packs", file), "utf-8");
    // Any `raw: {` literal in the source is a hand-typed vendor block — forbidden here.
    const handRaw = (src.match(/\braw:\s*\{/g) ?? []).length;
    expect(handRaw, `${file} has ${handRaw} hand-authored raw block(s); use the emitters`).toBe(0);
  });

  it("clipboardClipper still builds a coherent, correct incident from emitters only", () => {
    const s = buildClipboardClipperScenario();
    expect(s.events.length).toBe(8);
    // the whole chain lands on one company host, correctly correlated
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-5528");
    expect(inv.processes.some(p => p.name === "cmd.exe" && p.ppid === 6214)).toBe(true);
    expect(inv.processes.some(p => p.name === "clipsvc_helper.exe" && p.ppid === 6214)).toBe(true);
    expect(inv.detections.map(d => d.technique).sort()).toEqual(["T1059.003", "T1115", "T1204.002"]);
    const payload = inv.processes.find(p => p.pid === inv.answer.pid);
    expect(payload?.name).toBe("clipsvc_helper.exe");
    // one hash → one file across the whole pack
    const byHash = new Map<string, Set<string>>();
    for (const e of s.events) {
      const h = e.process?.hash?.sha256 ?? e.file?.sha256;
      const nm = e.process?.name ?? e.file?.name;
      if (h && nm) { const set = byHash.get(h) ?? new Set(); set.add(nm); byHash.set(h, set); }
    }
    expect([...byHash.values()].every(n => n.size === 1)).toBe(true);
  });

  it("trojanizedInstallerKeylogger still builds a coherent incident from emitters only (CrowdStrike + PAN + Sentinel)", () => {
    const s = buildTrojanizedInstallerKeyloggerScenario();
    expect(s.events.length).toBe(10);
    // three vendors, all emitter-authored
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "CrowdStrike Falcon", "Palo Alto Networks PAN-OS", "Microsoft Sentinel",
    ]));
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-2290");
    // the exact delivery tree: explorer -> SwiftPDF_Setup(7120) -> winupd_helper(7688)
    expect(inv.processes.some(p => p.name === "winupd_helper.exe" && p.ppid === 7120)).toBe(true);
    const payload = inv.processes.find(p => p.pid === inv.answer.pid);
    expect(payload?.name).toBe("winupd_helper.exe");
    // the Sentinel enrichment carries its ExtendedProperties arrays intact
    const ctx = s.events.find(e => e.id === "evt_tik_10_siem_context");
    expect(ctx?.raw?.["ExtendedProperties.Local Admin Rights"]).toBe("false");
    expect(ctx?.raw?.["AlertName"]).toBe("EndpointSoftwareChange_UnsignedPersistence");
  });

  it("seoPoisonedInstaller still builds a coherent incident from emitters only (MDE + PAN)", () => {
    const s = buildSeoPoisonedInstallerScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Microsoft Defender for Endpoint", "Palo Alto Networks PAN-OS",
    ]));
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-3312");
    // exact loader tree: explorer -> PuTTY-0.83-installer(7744) -> upd_helper(7801)
    expect(inv.processes.some(p => p.name === "upd_helper.exe" && p.ppid === 7744)).toBe(true);
    // the "Login Data" credential copy keeps no hash + its technique + is a feed alert
    const cred = s.events.find(e => e.id === "evt_spi_08_cred_copy");
    expect(cred?.file?.sha256).toBeUndefined();
    expect(cred?.mitre_technique).toBe("T1555.003");
    // the Defender incident alert carries its rich fields and no process node
    const alert = s.events.find(e => e.id === "evt_spi_10_alert");
    expect(alert?.raw?.["malware.name"]).toBe("Trojan:Win32/Rhadesta.SP!MTB");
    expect(alert?.raw?.["remediation.action"]).toBe("Quarantine");
    expect(alert?.process).toBeUndefined();
    // the PAN exfil is an outbound POST to the C2
    const exfil = s.events.find(e => e.id === "evt_spi_09_exfil");
    expect(exfil?.raw?.["pan.http_method"]).toBe("POST");
    expect(exfil?.raw?.["url.domain"]).toBe("cdn-assets-relay92.net");
  });
});
