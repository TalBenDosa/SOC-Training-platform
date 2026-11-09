/**
 * Native records the Live Feed shows (docs/LOG-REALISM-STANDARD.md):
 *  - R2: a story's own binary on DeviceProcessEvents carries an MD5, as a fleet binary does.
 *  - R5: an external party with no authored address gets a documentation address.
 */
import { describe, it, expect } from "vitest";
import type { TelemetryEvent } from "@/lib/sim/types";
import { nativeView } from "@/lib/logs/native";
import { makeCtx } from "@/lib/logs/native/ctx";
import { publicIpForDomain, egressIp } from "./firewall-shared";

describe("Live Feed native records", () => {
  it("MDE: a story binary with a SHA-256 has an MD5 too (R2)", () => {
    const ev = {
      id: "t_mde_md5", ts: "2026-11-09T09:00:00.000Z", source: "edr", vendor: "Microsoft Defender for Endpoint", event_type: "process_create",
      severity: "high", hostname: "WS-FIN-2847", user_email: "j.chen@nexacorp.com",
      process: { name: "upd.exe", path: "C:\\Users\\j.chen\\AppData\\Local\\Temp\\upd.exe", pid: 4242, cmdline: "upd.exe /s", hash: { sha256: "ab".repeat(32) } },
    } as unknown as TelemetryEvent;
    const rec = (nativeView(ev, "nexacorp")!.log.record as { properties: Record<string, unknown> }).properties;
    expect(rec.SHA256).toBe("ab".repeat(32));
    expect(String(rec.MD5)).toMatch(/^[0-9a-f]{32}$/);
  });
  it("derived external addresses and every company egress are documentation addresses (R5)", () => {
    const doc = /^(192\.0\.2|198\.51\.100|203\.0\.113)\./;
    for (const c of ["nexacorp", "rocketstack", "medcore", "globallogis", "quantumbank", "vantageindustrial", "some-named-org"]) {
      const ctx = makeCtx(c);
      expect(egressIp(ctx)).toMatch(doc);
      expect(publicIpForDomain(ctx, "zoom.us")).toMatch(doc);
    }
  });
});
