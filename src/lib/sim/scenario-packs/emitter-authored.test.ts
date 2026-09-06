import { describe, it, expect } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { buildClipboardClipperScenario } from "./clipboardClipper";
import { buildTrojanizedInstallerKeyloggerScenario } from "./trojanizedInstallerKeylogger";
import { buildSeoPoisonedInstallerScenario } from "./seoPoisonedInstaller";
import { buildDriveByBrowserMinerScenario } from "./driveByBrowserMiner";
import { buildBruteForceSingleAccountScenario } from "./bruteForceSingleAccount";
import { buildInvestigationsFromScenario } from "@/lib/edr/fromLiveStory";

// Packs that have been fully converted to the vendor emitters. Each MUST stay 100%
// emitter-authored — no hand-typed `raw: { … }` block may creep back in, because that
// is exactly the drift the emitter layer exists to prevent (a hand-typed field can be
// wrong; an emitter-rendered one is registry-correct by construction).
const FULLY_EMITTER_AUTHORED = [
  "clipboardClipper.ts", "trojanizedInstallerKeylogger.ts", "seoPoisonedInstaller.ts",
  "fakeBrowserUpdate.ts", "clickFixFakeCaptcha.ts", "driveByBrowserMiner.ts",
  "bruteForceSingleAccount.ts",
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

  it("driveByBrowserMiner still builds a coherent incident from emitters only (CS + PAN, csAlert + panConnection)", () => {
    const s = buildDriveByBrowserMinerScenario();
    expect(s.events.length).toBe(8);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "CrowdStrike Falcon", "Palo Alto Networks PAN-OS",
    ]));
    // the WebSocket tunnel is a net_connection with app=websocket (panConnection)
    const ws = s.events.find(e => e.id === "evt_dbm_05_ws_open");
    expect(ws?.event_type).toBe("net_connection");
    expect(ws?.raw?.["pan.app"]).toBe("websocket");
    // the traffic-end summary carries the duration (panConnection end)
    const wsClose = s.events.find(e => e.id === "evt_dbm_07_ws_close");
    expect(wsClose?.raw?.["pan.elapsed_time"]).toBe("1440");
    // the Falcon alert is a behavioural summary with no process node (csAlert)
    const alert = s.events.find(e => e.id === "evt_dbm_08_edr_alert");
    expect(alert?.raw?.["malware.category"]).toBe("cryptominer");
    expect(alert?.process).toBeUndefined();
    // the renderer process is present and the console opens on the right host
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("LAP-6690");
    expect(inv.processes.some(p => p.name === "chrome.exe" && p.pid === 8842)).toBe(true);
  });

  it("bruteForceSingleAccount builds a coherent AD incident from emitters only (Windows Security + CrowdStrike + PAN + Sentinel)", () => {
    const s = buildBruteForceSingleAccountScenario();
    expect(s.events.length).toBe(10);
    expect(new Set(s.events.map(e => e.vendor))).toEqual(new Set([
      "Palo Alto Networks PAN-OS", "Windows Security", "CrowdStrike Falcon", "Microsoft Sentinel",
    ]));
    // the two SubStatus codes that carry the whole lesson (no-user vs bad-password)
    const wrongUser = s.events.find(e => e.id === "evt_bf_02_fail_wrong_user");
    expect(wrongUser?.raw?.["winlog.event_data.SubStatus"]).toBe("0xC0000064");
    expect(wrongUser?.user_email).toBeUndefined();      // the account never existed → no mailbox
    const burst = s.events.find(e => e.id === "evt_bf_03_fail_burst");
    expect(burst?.raw?.["winlog.event_data.SubStatus"]).toBe("0xC000006A");
    // the 4624 success is the incident
    const success = s.events.find(e => e.id === "evt_bf_05_auth_success");
    expect(success?.event_type).toBe("auth_success");
    expect(success?.raw?.["winlog.event_id"]).toBe("4624");
    // the net.exe lateral-movement detection is alert-grade and lives in the EDR console
    const netUse = s.events.find(e => e.id === "evt_bf_07_net_use");
    expect(netUse?.is_detection).toBe(true);
    expect(netUse?.edr_scope).toBe("edr");
    expect(netUse?.process?.name).toBe("net.exe");
    // the Sentinel enrichment keeps its 90-day share baseline
    const ctx = s.events.find(e => e.id === "evt_bf_10_siem_context");
    expect(ctx?.raw?.["AlertName"]).toBe("ExternalAuthenticationBurst_SingleAccount");
    expect(ctx?.raw?.["ExtendedProperties.Lockout Policy Applied"]).toBe("false");
    // one host, correlated: the EDR console opens on the RDP server
    const inv = buildInvestigationsFromScenario({ title: s.title, events: s.events })[0];
    expect(inv.host.name).toBe("SRV-RDS-02");
  });
});
