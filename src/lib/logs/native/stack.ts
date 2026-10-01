/**
 * A session's data-source stack: which native source renders each category.
 * One vendor per category (spec §6.3). The default stack comes from the company
 * profile's declared architecture; the team-session builder (spec §3) will let
 * staff override it per category.
 */
import type { TelemetryEvent } from "@/lib/sim/types";
import type { SourceId } from "./types";

export type StackCategory =
  | "edr" | "firewall" | "vpn" | "proxy" | "dns" | "idp" | "onprem_ad" | "collab"
  | "email_security" | "cloud" | "k8s" | "pam" | "host_telemetry" | "linux" | "itsm";

export type Stack = Partial<Record<StackCategory, SourceId>>;

/** Default stacks for the five built-in companies (from companyProfilesMeta architecture). */
export const COMPANY_STACKS: Record<string, Stack> = {
  nexacorp: { edr: "mde", firewall: "paloalto", vpn: "globalprotect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", dns: "windows_dns", cloud: "azure_activity", host_telemetry: "sysmon", itsm: "servicenow" },
  rocketstack: { edr: "crowdstrike", firewall: "fortigate", vpn: "cloudflare_access", idp: "okta", collab: "google_workspace",
    cloud: "aws_cloudtrail", k8s: "k8s_audit", linux: "linux_auditd", itsm: "servicenow" },
  medcore: { edr: "sentinelone", firewall: "checkpoint", vpn: "anyconnect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", dns: "infoblox", cloud: "azure_activity", itsm: "servicenow" },
  globallogis: { edr: "sophos", firewall: "cisco_ftd", vpn: "anyconnect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", cloud: "aws_cloudtrail", host_telemetry: "sysmon", linux: "linux_auditd", itsm: "servicenow" },
  quantumbank: { edr: "crowdstrike", firewall: "paloalto", vpn: "zscaler_zpa", proxy: "zscaler_zia", idp: "okta",
    collab: "m365", email_security: "proofpoint", cloud: "aws_cloudtrail", pam: "cyberark", itsm: "servicenow" },
};

const has = (ev: TelemetryEvent, ...needles: string[]) => {
  const v = (ev.vendor ?? "").toLowerCase();
  return needles.some(n => v.includes(n));
};

/**
 * Which stack category an event belongs to, or null when no native module covers
 * it yet (WAF, DLP, UEBA, DB monitoring, virtualization, VCS, HR … keep their
 * legacy rendering until cards exist for them).
 */
export function categoryOf(ev: TelemetryEvent): StackCategory | null {
  switch (ev.source as string) {
    case "edr": case "av": return "edr";
    case "firewall": case "ids": return "firewall";
    case "vpn": return "vpn";
    case "proxy": return "proxy";
    case "dns": return "dns";
    case "sysmon": return "host_telemetry";
    case "linux_audit": return "linux";
    case "ad": case "windows_security": return "onprem_ad";
    case "okta": case "mfa": return "idp";
    case "o365": case "exchange": case "sharepoint":
      return has(ev, "entra", "azure active directory", "azure ad") ? "idp" : "collab";
    case "gws": return "collab";
    case "email_gateway": return "email_security";
    case "cloudtrail": case "cloud_azure": case "cloud_gcp":
      if (has(ev, "entra", "azure active directory", "azure ad")) return "idp";
      return "cloud";
    case "k8s_audit": return "k8s";
    case "iam": return has(ev, "cyberark") ? "pam" : has(ev, "okta") ? "idp" : has(ev, "entra", "azure") ? "idp" : null;
    case "soar": return has(ev, "servicenow") ? "itsm" : null;
    case "siem": return has(ev, "guardduty") ? "cloud" : null;
    default: return null;
  }
}

/**
 * The native source that renders `ev` under `stack`. Cloud is per-provider: an AWS
 * event stays AWS even on an Azure-first stack (GuardDuty findings → aws_guardduty).
 */
export function sourceFor(ev: TelemetryEvent, stack: Stack): SourceId | null {
  const cat = categoryOf(ev);
  if (!cat) return null;
  if (cat === "cloud") {
    if (has(ev, "guardduty")) return "aws_guardduty";
    if (ev.source === "cloudtrail" || has(ev, "aws", "cloudtrail")) return "aws_cloudtrail";
    if (ev.source === "cloud_gcp" || has(ev, "google cloud", "gcp")) return "gcp_audit";
    return "azure_activity";
  }
  if (cat === "onprem_ad") return "windows_security";
  return stack[cat] ?? nativeDefault(ev, cat);
}

/** Fall back to the vendor the event was authored for. */
function nativeDefault(ev: TelemetryEvent, cat: StackCategory): SourceId | null {
  switch (cat) {
    case "edr": return has(ev, "sentinelone") ? "sentinelone" : has(ev, "sophos") ? "sophos" : has(ev, "defender") ? "mde" : "crowdstrike";
    case "firewall": return has(ev, "forti") ? "fortigate" : has(ev, "check point", "checkpoint") ? "checkpoint" : has(ev, "asa") ? "cisco_asa" : has(ev, "cisco", "firepower") ? "cisco_ftd" : "paloalto";
    case "vpn": return has(ev, "anyconnect") ? "anyconnect" : has(ev, "forti") ? "fortigate_sslvpn" : has(ev, "zscaler") ? "zscaler_zpa" : has(ev, "cloudflare") ? "cloudflare_access" : "globalprotect";
    case "proxy": return "zscaler_zia";
    case "dns": return has(ev, "infoblox") ? "infoblox" : "windows_dns";
    case "idp": return has(ev, "okta") ? "okta" : "entra";
    case "collab": return ev.source === "gws" ? "google_workspace" : "m365";
    case "email_security": return has(ev, "proofpoint") ? "proofpoint" : "defender_o365";
    case "k8s": return "k8s_audit";
    case "pam": return "cyberark";
    case "host_telemetry": return "sysmon";
    case "linux": return "linux_auditd";
    case "itsm": return "servicenow";
    default: return null;
  }
}
