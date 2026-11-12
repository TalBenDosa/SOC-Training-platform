// No product picker choice may leave a session with products that cannot run together
// (Tal, 2026-11-07: a FortiGate shop was offered GlobalProtect, which only runs on PAN-OS).
import { describe, it, expect } from "vitest";
import { nextStack } from "@/components/training/StackPicker";
import { COMPANY_STACKS, STACK_CHOICES, coherentStack, vpnFitsFirewall, withFittingRemoteAccess, type Stack } from "./stack";
import { envForConsole, stackForConsole } from "@/lib/team/investigationConsole";
import type { SourceId } from "./types";

const merged = (company: string, delta: Stack) => coherentStack({ ...(COMPANY_STACKS[company] ?? {}), ...delta });
const opts = (c: string) => STACK_CHOICES.find(x => x.category === c)!.options as SourceId[];

describe("remote access follows the firewall", () => {
  it("a vendor's own VPN runs only on that vendor's firewall", () => {
    expect(vpnFitsFirewall("globalprotect", "paloalto")).toBe(true);
    expect(vpnFitsFirewall("globalprotect", "fortigate")).toBe(false);
    expect(vpnFitsFirewall("fortigate_sslvpn", "fortigate")).toBe(true);
    expect(vpnFitsFirewall("fortigate_sslvpn", "cisco_ftd")).toBe(false);
    expect(vpnFitsFirewall("anyconnect", "paloalto")).toBe(false);
    expect(vpnFitsFirewall("zscaler_zpa", "checkpoint")).toBe(true);
    expect(vpnFitsFirewall("cloudflare_access", "fortigate")).toBe(true);
  });

  it("changing the firewall brings its VPN, changing the VPN brings its firewall", () => {
    expect(withFittingRemoteAccess({ firewall: "fortigate", vpn: "globalprotect" }, "firewall").vpn).toBe("fortigate_sslvpn");
    expect(withFittingRemoteAccess({ firewall: "fortigate", vpn: "globalprotect" }, "vpn").firewall).toBe("paloalto");
    expect(withFittingRemoteAccess({ firewall: "fortigate", vpn: "globalprotect" }).vpn).toBe("fortigate_sslvpn");
  });

  it("every default company stack is already coherent, so existing sessions do not change", () => {
    for (const [company, stack] of Object.entries(COMPANY_STACKS)) expect(vpnFitsFirewall(stack.vpn, stack.firewall), company).toBe(true);
  });

  it("no pair of choices in the picker leaves a conflict", () => {
    for (const company of Object.keys(COMPANY_STACKS)) {
      for (const fw of opts("firewall")) for (const vpn of opts("vpn")) {
        for (const first of ["firewall", "vpn"] as const) {
          const second = first === "firewall" ? "vpn" : "firewall";
          const a = nextStack(company, merged(company, {}), first, first === "firewall" ? fw : vpn, false);
          const b = nextStack(company, merged(company, a.stack), second, second === "firewall" ? fw : vpn, a.forcedMail);
          const s = merged(company, b.stack);
          expect(vpnFitsFirewall(s.vpn, s.firewall), `${company} ${fw} ${vpn}`).toBe(true);
        }
      }
    }
  });
});

describe("Sentinel's own requirements", () => {
  it("always runs Defender for Endpoint, whatever EDR was chosen", () => {
    for (const edr of opts("edr")) expect(stackForConsole({ edr }, "sentinel").edr).toBe("mde");
    expect(stackForConsole({ edr: "crowdstrike" }, "edr").edr).toBe("crowdstrike");
  });

  it("an organization on Sentinel runs Azure (and no other cloud), and an EDR session is left alone", () => {
    const env = { platforms: ["aws" as const], industry: "general" as const };
    expect(envForConsole(env, "sentinel").platforms).toEqual(["azure"]);
    expect(envForConsole(env, "edr")).toBe(env);
    expect(envForConsole(null, "sentinel")).toBeNull();
  });
});
