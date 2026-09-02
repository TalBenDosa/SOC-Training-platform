/**
 * Company metadata — the LIGHT half of the old companyProfiles.ts.
 *
 * This file holds only the small, render-time data: the two interfaces and the
 * company profile records (name, industry, architecture — a few KB total). The
 * heavy per-company EVENT POOLS (COMPANY_EVENTS / COMPANY_ATTACKS and their
 * thousands of TelemetryEvents) stay in companyProfiles.ts, which the dashboard
 * now loads LAZILY (only when a training shift starts) — see dashboard/simData.ts.
 *
 * Why split: the dashboard is a client component, so anything it imports
 * statically ships in its first-load JS. It needs these profiles to render the
 * Topbar, company selector and source filters immediately, but does NOT need the
 * ~700KB of event data until the analyst presses "Start Training". A module is
 * the unit of code-splitting, so the light and heavy halves must live in
 * separate files for the bundler to keep the heavy one out of first load.
 */
import type { TelemetryEvent } from "@/lib/sim/types";

// ─── Company metadata ─────────────────────────────────────────────────────────

export interface CompanyArchitecture {
  edr:      string;   // e.g. "Microsoft Defender for Endpoint"
  cloud:    string;   // e.g. "Azure"
  idp:      string;   // e.g. "Azure Active Directory"
  email:    string;   // e.g. "Microsoft 365"
  firewall: string;   // e.g. "Palo Alto NGFW"
  vpn:      string;   // e.g. "GlobalProtect"
  sources:  string[]; // SIEM source keys active in this environment
}

export interface CompanyProfile {
  id:           string;
  name:         string;
  tagline:      string;
  industry:     string;
  size:         number;
  hq:           string;
  description:  string;
  gradient:     string;   // Tailwind gradient classes for card accent
  architecture: CompanyArchitecture;
  events:       TelemetryEvent[];  // benign background event pool
}

// ─────────────────────────────────────────────────────────────────────────────
// Company 1 — NexaCorp Financial Ltd.
// Microsoft-centric: MDE + Azure AD + O365 + Palo Alto
// (events populated by page.tsx from benignEvents.ts)
// ─────────────────────────────────────────────────────────────────────────────

export const NEXACORP_PROFILE: Omit<CompanyProfile, "events"> = {
  id:          "nexacorp",
  name:        "NexaCorp Financial Ltd.",
  tagline:     "Investment Management & Trading",
  industry:    "Financial Services",
  size:        1200,
  hq:          "London, UK",
  description: "Mid-size investment management firm. Heavily regulated (FCA/MiFID II). Full Microsoft stack with Palo Alto perimeter. On-prem AD synced to Azure AD.",
  gradient:    "from-blue-600 to-cyan-500",
  architecture: {
    edr:      "Microsoft Defender for Endpoint",
    cloud:    "Azure",
    idp:      "Azure Active Directory (Entra ID)",
    email:    "Microsoft 365 Exchange Online",
    firewall: "Palo Alto NGFW + GlobalProtect VPN",
    vpn:      "GlobalProtect",
    sources:  ["edr", "ad", "windows_security", "o365", "cloudtrail", "firewall", "vpn", "sysmon", "dns"]
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Company registry — profile metadata only (event pools live in companyProfiles.ts)
// ─────────────────────────────────────────────────────────────────────────────

export const COMPANY_PROFILES: Omit<CompanyProfile, "events">[] = [
  {
    ...NEXACORP_PROFILE
  },
  {
    id:          "rocketstack",
    name:        "RocketStack Technologies",
    tagline:     "Cloud-native SaaS Platform",
    industry:    "Technology / SaaS",
    size:        185,
    hq:          "Tel Aviv, Israel",
    description: "Fast-growing SaaS startup. Cloud-native on AWS. Mostly macOS endpoints. Okta for zero-trust identity. CrowdStrike Falcon protecting a mixed Mac/Linux fleet.",
    gradient:    "from-orange-500 to-pink-500",
    architecture: {
      edr:      "CrowdStrike Falcon",
      cloud:    "AWS",
      idp:      "Okta",
      email:    "Google Workspace",
      firewall: "Fortinet FortiGate 100F",
      vpn:      "Cloudflare Access (Zero Trust)",
      sources:  ["edr", "okta", "cloudtrail", "firewall", "dns", "gws"]
    }
  },
  {
    id:          "medcore",
    name:        "MedCore Regional Hospital",
    tagline:     "Healthcare Network — 6 Facilities",
    industry:    "Healthcare",
    size:        3800,
    hq:          "Amsterdam, Netherlands",
    description: "Regional hospital network with strict HIPAA/NEN7510 compliance. Hybrid Azure + on-prem AD. SentinelOne on clinical workstations. Critical medical devices on separate VLAN.",
    gradient:    "from-emerald-500 to-teal-500",
    architecture: {
      edr:      "SentinelOne Singularity",
      cloud:    "Azure (hybrid)",
      idp:      "Active Directory + Azure AD Hybrid Join",
      email:    "Microsoft 365 Exchange Online",
      firewall: "Check Point NGFW R81.20",
      vpn:      "Cisco AnyConnect",
      sources:  ["edr", "ad", "o365", "cloudtrail", "firewall", "vpn", "dns"]
    }
  },
  {
    id:          "globallogis",
    name:        "GlobalLogis Distribution SA",
    tagline:     "European Logistics & Supply Chain",
    industry:    "Logistics / Manufacturing",
    size:        7500,
    hq:          "Frankfurt, Germany",
    description: "Large logistics operator with warehouses across Europe. Mixed IT/OT environment. Sophos protecting Windows fleet + warehouse terminals. AWS EU for ERP/WMS workloads. Cisco perimeter.",
    gradient:    "from-yellow-500 to-amber-600",
    architecture: {
      edr:      "Sophos Intercept X",
      cloud:    "AWS (EU)",
      idp:      "Active Directory (multi-domain forest)",
      email:    "Microsoft 365",
      firewall: "Cisco ASA + Firepower IPS",
      vpn:      "Cisco AnyConnect",
      sources:  ["edr", "ad", "o365", "cloudtrail", "firewall", "vpn", "sysmon", "dns"]
    }
  },
  {
    id:          "quantumbank",
    name:        "QuantumBank Corp.",
    tagline:     "Private Banking & Asset Management",
    industry:    "Banking / Finance",
    size:        520,
    hq:          "Zurich, Switzerland",
    description: "Private bank with PCI-DSS Level 1 compliance. Security-first architecture: CrowdStrike Falcon Elite, FIDO2-only auth, CyberArk PAM for privileged access, Zscaler ZIA for all egress. AWS GovCloud.",
    gradient:    "from-violet-600 to-purple-700",
    architecture: {
      edr:      "CrowdStrike Falcon Elite",
      cloud:    "AWS GovCloud",
      idp:      "Okta + CyberArk PAM",
      email:    "Microsoft 365 (DMARC enforced)",
      firewall: "Palo Alto NGFW (HA pair)",
      vpn:      "Zscaler Private Access",
      sources:  ["edr", "okta", "cloudtrail", "firewall", "proxy", "dns"]
    }
  },
];
