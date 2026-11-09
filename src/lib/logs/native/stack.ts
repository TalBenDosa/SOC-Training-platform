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
  | "email_security" | "cloud" | "k8s" | "pam" | "host_telemetry" | "linux" | "itsm" | "waf" | "web_server"
  | "db_monitor" | "ueba";

export type Stack = Partial<Record<StackCategory, SourceId>> & {
  /**
   * Where the session's SIEM reads product detections from. Not a category and never a
   * choice in the picker: stackForConsole sets it for a session that runs on Sentinel.
   * Absent on an EDR session and on every older session.
   */
  detection_feed?: "ms_graph";
};

/** Default stacks for the five built-in companies (from companyProfilesMeta architecture). */
export const COMPANY_STACKS: Record<string, Stack> = {
  nexacorp: { edr: "mde", firewall: "paloalto", vpn: "globalprotect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", dns: "windows_dns", cloud: "azure_activity", host_telemetry: "sysmon", itsm: "servicenow",
    waf: "azure_waf", web_server: "iis" },
  rocketstack: { edr: "crowdstrike", firewall: "fortigate", vpn: "cloudflare_access", idp: "okta", collab: "google_workspace",
    cloud: "aws_cloudtrail", k8s: "k8s_audit", linux: "linux_auditd", itsm: "servicenow",
    waf: "aws_waf", web_server: "nginx" },
  medcore: { edr: "sentinelone", firewall: "checkpoint", vpn: "anyconnect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", dns: "infoblox", cloud: "azure_activity", itsm: "servicenow",
    waf: "azure_waf", web_server: "iis" },
  globallogis: { edr: "sophos", firewall: "cisco_ftd", vpn: "anyconnect", idp: "entra", onprem_ad: "windows_security",
    collab: "m365", email_security: "defender_o365", cloud: "aws_cloudtrail", host_telemetry: "sysmon", linux: "linux_auditd", itsm: "servicenow",
    waf: "aws_waf", web_server: "nginx" },
  quantumbank: { edr: "crowdstrike", firewall: "paloalto", vpn: "zscaler_zpa", proxy: "zscaler_zia", idp: "okta",
    collab: "m365", email_security: "proofpoint", cloud: "aws_cloudtrail", pam: "cyberark", itsm: "servicenow",
    waf: "aws_waf", web_server: "nginx" },
};

const has = (ev: TelemetryEvent, ...needles: string[]) => {
  const v = (ev.vendor ?? "").toLowerCase();
  return needles.some(n => v.includes(n));
};

/**
 * Which stack category an event belongs to, or null when no native module covers
 * it yet (DLP, virtualization, VCS, HR, WAF events written for a named product, and the
 * database / UEBA products without a module keep their legacy rendering).
 */
export function categoryOf(ev: TelemetryEvent): StackCategory | null {
  switch (ev.source as string) {
    case "edr": case "av": return "edr";
    case "firewall": return "firewall";
    // A firewall's threat log is the firewall's; a Zeek / Corelight sensor's protocol log is its
    // own product (no native card yet) - never relabelled as the shop's firewall.
    case "ids": return has(ev, "zeek", "corelight") ? null : "firewall";
    case "vpn": return "vpn";
    case "proxy": return "proxy";
    case "dns": return "dns";
    case "sysmon": return "host_telemetry";
    case "linux_audit": return "linux";
    case "ad": case "windows_security": return "onprem_ad";
    case "okta": case "mfa": return "idp";
    case "o365": case "exchange": case "sharepoint": {
      if (has(ev, "entra", "azure active directory", "azure ad")) return "idp";
      // Mail-flow / gateway verdicts authored under source "o365" (Defender for
      // Office 365 vendor, or UAL-vendor MessageDelivered / SpamFiltered) are
      // email-security records, not Unified Audit Log records.
      const op = String((ev.raw ?? {})["data.office365.Operation"] ?? (ev.raw ?? {})["Operation"] ?? "");
      if (has(ev, "defender for office", "proofpoint") || /^(MessageDelivered|SpamFiltered)$/.test(op)) return "email_security";
      return "collab";
    }
    case "gws": return "collab";
    case "email_gateway": return "email_security";
    // A WAF event authored for the session's WAF (WEB_WAF_VENDOR). One authored for a named
    // product (AWS WAF, Imperva ...) keeps its legacy view, as every story written before the
    // native modules does.
    case "waf": return has(ev, "web application firewall") ? "waf" : null;
    case "web_server": return "web_server";
    case "cloudtrail": case "cloud_azure": case "cloud_gcp":
      if (has(ev, "entra", "azure active directory", "azure ad")) return "idp";
      return "cloud";
    case "k8s_audit": return "k8s";
    case "iam": return has(ev, "cyberark") ? "pam" : has(ev, "okta") ? "idp" : has(ev, "entra", "azure") ? "idp" : null;
    case "soar": return has(ev, "servicenow") ? "itsm" : null;
    case "siem": return has(ev, "guardduty") ? "cloud" : null;
    // Database audit and DAM products with a native module (SQL Server Audit, Guardium, MySQL Enterprise
    // Audit). Imperva DAM, Azure SQL Auditing and application audit logs keep their raw view.
    case "db_monitor": return dbMonitorSource(ev) ? "db_monitor" : null;
    // UEBA products with a native module. Microsoft Sentinel UEBA (BehaviorAnalytics) and Purview
    // Insider Risk keep their own views.
    case "ueba": return uebaSource(ev) ? "ueba" : null;
    default: return null;
  }
}

/**
 * A database audit product is the database's own feature or the DAM appliance in front of it: the row
 * stays that product's record whatever else the session runs (never a stack choice).
 */
function dbMonitorSource(ev: TelemetryEvent): SourceId | null {
  if (has(ev, "guardium")) return "guardium";
  if (has(ev, "sql server audit", "mssql audit", "microsoft sql audit")) return "mssql_audit";
  if (has(ev, "mysql enterprise audit", "mysql audit")) return "mysql_audit";
  return null;
}
/** A UEBA product's own record (its scores and models are its own: never relabelled as another UEBA). */
function uebaSource(ev: TelemetryEvent): SourceId | null {
  if (has(ev, "exabeam")) return "exabeam";
  if (has(ev, "securonix")) return "securonix";
  return null;
}

/**
 * The native source that renders `ev` under `stack`: the event's product (productSourceFor),
 * except that a session reading its detections from Microsoft Graph shows a product detection
 * of a Microsoft product as its Graph alert. Raw logs keep their own format.
 */
export function sourceFor(ev: TelemetryEvent, stack: Stack): SourceId | null {
  if (stack.detection_feed === "ms_graph" && microsoftProductOf(ev, stack)) return "ms_graph";
  return productSourceFor(ev, stack);
}

/** The stack without its detection feed: what picks the products, labels the rows and fits the stories. */
export function withoutDetectionFeed(stack: Stack): Stack {
  const { detection_feed: _feed, ...products } = stack;
  void _feed;
  return products;
}

const ALERT_EVENT_TYPES = new Set(["edr_alert", "av_detection", "av_quarantine", "av_blocked", "dlp_alert", "dlp_block"]);

/**
 * Did a product raise this event as an alert? The test the Sentinel workspace raises a
 * SecurityAlert on (src/lib/sentinel/workspace.ts isProductDetection): is_detection, an alert
 * event type, a SIEM row that names its alert, or a Defender for Cloud alert. It reads the
 * public payload only, so a false-positive detection and an attack detection pass alike.
 */
export function isProductDetection(ev: TelemetryEvent): boolean {
  if (ev.is_detection || ALERT_EVENT_TYPES.has(ev.event_type)) return true;
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  if (ev.source === "siem" && typeof r["AlertName"] === "string" && r["AlertName"]) return true;
  return productSourceFor(ev, {}) === "azure_activity" && !!(r["azure.alert.alertType"] || r["azure.alert.displayName"]);
}

/** The Microsoft security products that publish to the Graph alerts_v2 API. */
export type MicrosoftProduct = "defender_endpoint" | "entra_id_protection" | "defender_office" | "defender_cloud_apps"
  | "defender_identity" | "defender_cloud" | "purview_dlp" | "insider_risk" | "sentinel" | "defender_xdr";

/** A SecurityAlert row's ProductName column, old and current spellings: the product that raised the alert, whoever forwarded it. */
const NAMED_PRODUCT: Record<string, MicrosoftProduct> = {
  "Microsoft Defender Advanced Threat Protection": "defender_endpoint", "Microsoft Defender for Endpoint": "defender_endpoint",
  "Azure Active Directory Identity Protection": "entra_id_protection", "Microsoft Entra ID Protection": "entra_id_protection",
  "Office 365 Advanced Threat Protection": "defender_office", "Microsoft Defender for Office 365": "defender_office",
  "Microsoft Cloud App Security": "defender_cloud_apps", "Microsoft Defender for Cloud Apps": "defender_cloud_apps",
  "Azure Advanced Threat Protection": "defender_identity", "Microsoft Defender for Identity": "defender_identity",
  "Azure Security Center": "defender_cloud", "Microsoft Defender for Cloud": "defender_cloud",
  "Microsoft Data Loss Prevention": "purview_dlp",
  "Azure Sentinel": "sentinel", "Microsoft Sentinel": "sentinel",
  // An XDR session's team room shows the SIEM analytics as the console's own (src/lib/sentinel/xdrBrand.ts).
  "XDR Analytics": "sentinel",
};

/**
 * The Microsoft product that raises this detection under `stack`, or null when it is not a
 * product detection or the product is not Microsoft's (Okta, Proofpoint, a firewall). A product
 * the event names wins; otherwise the session's product for its category decides, so a
 * CrowdStrike-authored detection shown as Defender for Endpoint is Defender's alert.
 */
export function microsoftProductOf(ev: TelemetryEvent, stack: Stack): MicrosoftProduct | null {
  if (!isProductDetection(ev)) return null;
  const named = NAMED_PRODUCT[String((ev.raw ?? {})["ProductName"] ?? "")];
  if (named) return named;
  if (has(ev, "defender for identity")) return "defender_identity";
  if (has(ev, "defender for cloud apps")) return "defender_cloud_apps";
  if (has(ev, "defender for cloud")) return "defender_cloud";
  if (has(ev, "insider risk")) return "insider_risk";
  if (has(ev, "microsoft graph security")) return "defender_xdr";
  if (has(ev, "microsoft sentinel", "xdr analytics", "xdr ueba")) return "sentinel";
  if (ev.source === "dlp") return has(ev, "purview") ? "purview_dlp" : null;
  switch (productSourceFor(ev, stack)) {
    case "mde": return "defender_endpoint";
    case "entra": return "entra_id_protection";
    case "defender_o365": return "defender_office";
    // Microsoft 365 raises no alert of its own: its audit activity alerts through Defender for Cloud Apps.
    case "m365": return ev.source === "gws" ? null : "defender_cloud_apps";
    default: return null;
  }
}

/**
 * The source a session's SIEM feed shows this row under, when that is not the row's own
 * source: "ms_graph" for a detection read from Graph. A display fact, computed on the client:
 * the public payload keeps its source and vendor, so the alert queue, timing and scoring never see it.
 */
export function feedSourceOf(ev: TelemetryEvent, companyId: string, stack?: Stack): "ms_graph" | null {
  if (stack?.detection_feed !== "ms_graph") return null;
  const e = ev as TelemetryEvent & { _authored_source?: string; _authored_vendor?: string };
  const authored = { ...ev, source: (e._authored_source ?? ev.source) as TelemetryEvent["source"], vendor: e._authored_vendor ?? ev.vendor };
  return sourceFor(authored, coherentStack({ ...(COMPANY_STACKS[companyId] ?? {}), ...stack })) === "ms_graph" ? "ms_graph" : null;
}

/**
 * The product's own source for `ev`. Cloud is per-provider: an AWS event stays AWS even on an
 * Azure-first stack (GuardDuty findings → aws_guardduty).
 */
export function productSourceFor(ev: TelemetryEvent, stack: Stack): SourceId | null {
  // Microsoft Purview DLP exists only in Microsoft 365: its rule matches are Unified Audit Log records
  // (DLP.All) whatever the session's other products. Other DLP events keep the legacy view.
  if (ev.source === "dlp") return purviewRuleMatch(ev) ? "m365" : null;
  // Workday is the HR system of record: its activity log renders as Workday in every stack.
  if (ev.source === "hr") return /workday/i.test(ev.vendor ?? "") ? "workday" : null;
  const cat = categoryOf(ev);
  if (!cat) return null;
  if (cat === "cloud") {
    if (has(ev, "guardduty")) return "aws_guardduty";
    if (ev.source === "cloudtrail" || has(ev, "aws", "cloudtrail")) return "aws_cloudtrail";
    if (ev.source === "cloud_gcp" || has(ev, "google cloud", "gcp")) return "gcp_audit";
    return "azure_activity";
  }
  if (cat === "onprem_ad") return "windows_security";
  if (cat === "db_monitor") return dbMonitorSource(ev);
  if (cat === "ueba") return uebaSource(ev);
  // A story that shows the server's own process tree is bound to that OS, so the access log stays
  // that server's (nginx in front of php-fpm is not an IIS log). Only an unbound one follows the stack.
  if (cat === "web_server" && has(ev, "iis")) return "iis";
  if (cat === "web_server" && has(ev, "nginx")) return "nginx";
  return stack[cat] ?? nativeDefault(ev, cat);
}

/** A Purview DLP event that names the matched policy (see sources/_m365-dlp isDlpRuleMatch). */
function purviewRuleMatch(ev: TelemetryEvent): boolean {
  if (!/purview|microsoft 365|office 365/i.test(ev.vendor ?? "")) return false;
  const r = (ev.raw ?? {}) as Record<string, unknown>;
  const op = r["data.office365.Operation"] ?? r["Operation"];
  if (op !== undefined && op !== "DlpRuleMatch") return false;
  return ["data.office365.PolicyDetails.PolicyName", "data.office365.PolicyDetails[0].PolicyName", "PolicyDetails.PolicyName", "purview.PolicyName", "policy.name"]
    .some(k => r[k] !== undefined && r[k] !== null && r[k] !== "");
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
    case "waf": return "aws_waf";
    case "web_server": return "nginx";
    default: return null;
  }
}

// ── Vendor choice (spec §3, step 2) ──────────────────────────────────────────

/** Short product names shown in the feed and pickers (light - no module import). */
export const PRODUCT_LABEL: Partial<Record<SourceId, string>> = {
  crowdstrike: "CrowdStrike Falcon", mde: "Microsoft Defender for Endpoint", sentinelone: "SentinelOne", sophos: "Sophos Intercept X",
  paloalto: "Palo Alto Networks", fortigate: "Fortinet FortiGate", checkpoint: "Check Point", cisco_ftd: "Cisco Firepower (FTD)", cisco_asa: "Cisco ASA",
  globalprotect: "GlobalProtect", anyconnect: "Cisco AnyConnect", fortigate_sslvpn: "FortiGate SSL-VPN", zscaler_zpa: "Zscaler Private Access", cloudflare_access: "Cloudflare Access",
  entra: "Microsoft Entra ID", okta: "Okta", cyberark: "CyberArk PAM",
  m365: "Microsoft 365", google_workspace: "Google Workspace",
  defender_o365: "Microsoft Defender for Office 365", proofpoint: "Proofpoint TAP",
  windows_dns: "Windows DNS", infoblox: "Infoblox", zscaler_zia: "Zscaler Internet Access",
  aws_waf: "AWS WAF", azure_waf: "Azure WAF", iis: "Microsoft IIS", nginx: "nginx",
  ms_graph: "Microsoft Graph Security",
  mssql_audit: "Microsoft SQL Server Audit", guardium: "IBM Guardium", mysql_audit: "MySQL Enterprise Audit",
  exabeam: "Exabeam Advanced Analytics", securonix: "Securonix SNYPR",
};

/** The categories a trainer can switch, with the products the platform renders natively. */
export const STACK_CHOICES: { category: StackCategory; label: string; options: SourceId[]; note?: string }[] = [
  { category: "edr", label: "EDR", options: ["crowdstrike", "mde", "sentinelone", "sophos"],
    note: "Sophos streams no per-event DNS / network / file telemetry, so attacks that need that trail are not picked." },
  { category: "firewall", label: "Firewall", options: ["paloalto", "fortigate", "checkpoint", "cisco_ftd", "cisco_asa"] },
  { category: "vpn", label: "Remote access", options: ["globalprotect", "anyconnect", "fortigate_sslvpn", "zscaler_zpa", "cloudflare_access"],
    note: "ZPA and Cloudflare sign in through SAML - password failures appear in the identity provider's logs instead." },
  { category: "idp", label: "Identity provider", options: ["entra", "okta"] },
  { category: "collab", label: "Email & files", options: ["m365", "google_workspace"],
    note: "Google Workspace has no equivalent for Exchange inbox rules or mailbox delegation - those attacks are not picked." },
  { category: "email_security", label: "Email security", options: ["defender_o365", "proofpoint"] },
  { category: "dns", label: "DNS", options: ["windows_dns", "infoblox"] },
  { category: "waf", label: "Web application firewall", options: ["azure_waf", "aws_waf"],
    note: "A WAF comes with its cloud: Azure WAF needs Azure subscriptions, AWS WAF needs AWS, or web attacks are not picked for a named organization." },
  { category: "web_server", label: "Web server", options: ["iis", "nginx"],
    note: "Attacks that show the server's own processes keep the web server they were written on." },
];

/** Keep only known categories / products (client input is never trusted). */
/**
 * Products that can't coexist: Defender for Office 365 filters Exchange Online mail
 * only, so a Google Workspace tenant's mail security is Proofpoint (which fronts Gmail).
 */
export function coherentStack(s: Stack): Stack {
  return s.collab === "google_workspace" && s.email_security === "defender_o365" ? { ...s, email_security: "proofpoint" } : s;
}

/**
 * Remote access products that exist only on their vendor's own firewall: GlobalProtect is a PAN-OS
 * feature and FortiGate SSL VPN a FortiOS one. AnyConnect needs a Cisco head-end, which a Check Point
 * site can run beside its perimeter firewall, as MedCore does. ZPA and Cloudflare Access need none.
 */
const VPN_NEEDS_FIREWALL: Partial<Record<SourceId, { firewalls: SourceId[]; native: boolean }>> = {
  globalprotect: { firewalls: ["paloalto"], native: true },
  fortigate_sslvpn: { firewalls: ["fortigate"], native: true },
  anyconnect: { firewalls: ["cisco_ftd", "cisco_asa", "checkpoint"], native: false },
};

/** Whether this remote access product can run with this firewall. */
export function vpnFitsFirewall(vpn: SourceId | undefined, firewall: SourceId | undefined): boolean {
  const need = vpn ? VPN_NEEDS_FIREWALL[vpn] : undefined;
  return !need || !firewall || need.firewalls.includes(firewall);
}

/** The remote access product a firewall brings with it, for when the one chosen no longer fits. */
const FIREWALL_VPN: Partial<Record<SourceId, SourceId>> = {
  paloalto: "globalprotect", fortigate: "fortigate_sslvpn", cisco_ftd: "anyconnect", cisco_asa: "anyconnect", checkpoint: "anyconnect",
};

/**
 * Settles a firewall and a remote access product that cannot run together. The category the
 * person just changed wins, and the other one follows it. With no change named, as on the
 * server, the firewall wins. Existing sessions never pass through here: only a new choice does.
 */
export function withFittingRemoteAccess(s: Stack, changed?: StackCategory): Stack {
  if (vpnFitsFirewall(s.vpn, s.firewall)) return s;
  if (changed === "vpn" && s.vpn) return { ...s, firewall: VPN_NEEDS_FIREWALL[s.vpn]?.firewalls[0] };
  return { ...s, vpn: s.firewall ? FIREWALL_VPN[s.firewall] : s.vpn };
}

export function sanitizeStack(input: unknown): Stack {
  const out: Stack = {};
  if (!input || typeof input !== "object") return out;
  for (const c of STACK_CHOICES) {
    const v = (input as Record<string, unknown>)[c.category];
    if (typeof v === "string" && (c.options as string[]).includes(v)) out[c.category] = v as SourceId;
  }
  if ((input as Record<string, unknown>).detection_feed === "ms_graph") out.detection_feed = "ms_graph";
  return out;
}

// Product names that appear in authored descriptions, per category - rewritten to
// the chosen product so a row never says "Defender killed it" on a CrowdStrike shop.
const NAME_FAMILIES: Partial<Record<StackCategory, string[]>> = {
  // Microsoft Defender Antivirus / Windows Defender are the Windows built-in AV, present under any EDR
  // (passive mode beside Falcon / S1 / Sophos) - they are kept, not renamed (see BUILTIN_AV).
  edr: ["Microsoft Defender for Endpoint", "Microsoft Defender ATP", "Defender for Endpoint",
    "Microsoft Defender", "CrowdStrike Falcon Elite", "CrowdStrike Falcon", "CrowdStrike", "Falcon", "SentinelOne Singularity", "SentinelOne",
    "Sophos Intercept X", "Sophos", "Defender"],
  firewall: ["Palo Alto Networks", "Palo Alto NGFW", "Palo Alto", "PAN-OS", "Fortinet FortiGate", "FortiGate", "Fortinet", "Check Point",
    "Cisco Firepower", "Firepower", "Cisco ASA"],
  vpn: ["GlobalProtect", "Cisco AnyConnect", "AnyConnect", "Cisco Secure Client", "FortiGate SSL-VPN", "FortiClient", "Zscaler Private Access", "Cloudflare Access", "Cloudflare Zero Trust"],
  idp: ["Microsoft Entra ID", "Microsoft Entra", "Entra ID", "Entra", "Azure Active Directory", "Azure AD", "Okta"],
  email_security: ["Microsoft Defender for Office 365", "Defender for Office 365", "Proofpoint TAP", "Proofpoint"],
  dns: ["Infoblox", "Windows DNS"],
};
const COLLAB_TO_GOOGLE: [string, string][] = [
  ["Microsoft 365", "Google Workspace"], ["Office 365", "Google Workspace"], ["Microsoft Office", "Google Workspace"], ["SharePoint Online", "Google Drive"], ["SharePoint", "Google Drive"],
  ["OneDrive", "Google Drive"], ["Exchange Online", "Gmail"], ["Outlook", "Gmail"],
];
const COLLAB_TO_M365: [string, string][] = [["Google Workspace", "Microsoft 365"], ["Google Drive", "OneDrive"], ["Gmail", "Outlook"]];
/** Windows' own AV and its components: the same on every endpoint whatever the EDR. "Defender AV" is spelled out. */
const BUILTIN_AV = /(?<![A-Za-z])(?:(?:Microsoft|Windows) Defender (?:Antivirus|AV|Credential Guard|Firewall|SmartScreen|real-time protection)|Windows Defender|Defender (?:AV|Antivirus))(?![A-Za-z])/g;
/** Okta has no "Conditional Access" (its equivalent is the sign-on policy) and pushes MFA through Okta Verify. */
const IDP_TO_OKTA: [RegExp, string][] = [[/Conditional Access polic(y|ies)/g, "Okta sign-on polic$1"], [/Conditional Access/g, "Okta sign-on policy"], [/Microsoft Authenticator/g, "Okta Verify"],
  // Entra's admin role names → Okta's (Global Administrator is Okta's Super Administrator).
  [/Global Administrator/g, "Super Administrator"], [/Helpdesk Administrator/g, "Help Desk Administrator"]];
const IDP_TO_ENTRA: [RegExp, string][] = [[/Okta sign-on polic(y|ies)/g, "Conditional Access polic$1"], [/Okta Verify/g, "Microsoft Authenticator"],
  [/Super Administrator/g, "Global Administrator"], [/Help Desk Administrator/g, "Helpdesk Administrator"]];

/**
 * Artifacts only one product has - its OS, its own field names, its API paths. An
 * event that cites them was written about that product and can't be shown as
 * another one (a FortiOS API-bypass story is not a PAN-OS story).
 */
export const PRODUCT_LOCKS: Partial<Record<SourceId, RegExp>> = {
  fortigate: /FortiOS|FortiGuard|\bdata\.(?:user|srcip|dstip|action)\b|\/api\/v2\/(?:cmdb|monitor)\//,
  fortigate_sslvpn: /FortiOS|SSL-VPN|\/remote\/(?:login|logincheck)/,
  paloalto: /PAN-OS|WildFire|App-ID|Panorama/,
  globalprotect: /GlobalProtect portal|HIP (?:check|report|profile)/,
  checkpoint: /SmartConsole|SmartEvent|ThreatCloud/,
  cisco_asa: /%ASA-\d/,
  cisco_ftd: /%FTD-\d|Firepower Management Center/,
  crowdstrike: /Real Time Response|OverWatch/,
  mde: /Advanced Hunting|DeviceProcessEvents/,
  sentinelone: /Storyline|Deep Visibility/,
  sophos: /Sophos Central/,
  okta: /ThreatInsight/,
  entra: /non-interactive|Identity Protection/,
};

/** Microsoft 365 client software / endpoints - background noise a Google Workspace shop doesn't produce. */
export const M365_CLIENT_TEXT = /\b(?:Outlook|Teams|OneDrive|SharePoint|Microsoft 365|Office 365|Exchange Online)\b/;
export const M365_CLIENT_RECORD = /OUTLOOK\.EXE|Teams\.exe|ms-teams\.exe|OneDrive\.exe|office365\.com|teams\.microsoft\.com|sharepoint\.com|outlook\.office\.com/i;
export const MS_LOGIN_RECORD = /login\.microsoftonline\.com|login\.live\.com/i;

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
/** "a Okta sign-on policy" → "an Okta …", "an Microsoft 365 …" → "a Microsoft 365 …" next to a swapped-in name. */
function fixArticles(text: string, names: string[]): string {
  let out = text;
  for (const n of new Set(names)) {
    const an = /^[AEIO]/.test(n) || /^(?:Okta|Infoblox|Outlook|Office|Entra)/.test(n);
    out = out.replace(new RegExp(`(?<![A-Za-z])(a|an|A|An) (?=${escapeRe(n)}(?![A-Za-z]))`, "g"),
      (_m, art: string) => `${art[0] === "A" ? (an ? "An" : "A") : (an ? "an" : "a")} `);
  }
  return out;
}
function rewriteNames(text: string, pairs: [string, string][]): string {
  // Placeholders first (longest names first), then targets - a rewrite never re-matches its own output.
  const sorted = [...pairs].sort((a, b) => b[0].length - a[0].length);
  let out = text;
  sorted.forEach(([from], i) => { out = out.replace(new RegExp(`(?<![A-Za-z])${escapeRe(from)}(?![A-Za-z])`, "g"), `\u0000${i}\u0000`); });
  const done = out.replace(/\u0000(\d+)\u0000/g, (_m, i) => sorted[Number(i)][1]);
  return done === text ? text : fixArticles(done, sorted.map(p => p[1]));
}

/** Description with the category's product names switched to `sid`'s. */
export function rewriteProductText(text: string | undefined, cat: StackCategory, sid: SourceId): string | undefined {
  if (!text) return text;
  if (cat === "collab") return rewriteNames(text, sid === "google_workspace" ? COLLAB_TO_GOOGLE : COLLAB_TO_M365);
  const fam = NAME_FAMILIES[cat];
  const to = PRODUCT_LABEL[sid];
  if (!fam || !to) return text;
  let out = text;
  const kept: string[] = [];
  if (cat === "edr" && sid !== "mde") {
    out = out.replace(BUILTIN_AV, m => { kept.push(/^Defender (AV|Antivirus)$/.test(m) ? "Microsoft Defender Antivirus" : m); return `\u0000K${kept.length - 1}\u0000`; });
  }
  if (cat === "idp") for (const [re, by] of sid === "okta" ? IDP_TO_OKTA : IDP_TO_ENTRA) out = out.replace(re, by);
  // Replace with a unique placeholder first so a rewrite never re-matches its own output.
  for (const name of [...fam].sort((a, b) => b.length - a.length)) {
    out = out.replace(new RegExp(`(?<![A-Za-z])${escapeRe(name)}(?![A-Za-z])`, "g"), "\u0000P\u0000");
  }
  out = out.split("\u0000P\u0000").join(to).replace(/\u0000K(\d+)\u0000/g, (_m, i: string) => kept[Number(i)]);
  return out === text ? text : fixArticles(out, [to, "Okta sign-on policy", "Okta Verify", "Microsoft Authenticator", "Conditional Access", ...kept]);
}
