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

// ─── Per-company asset registry (R-01) ────────────────────────────────────────
// The hostname convention, primary internal subnet, DNS domain and NetBIOS realm
// each company actually uses in its SIEM feed (companyProfiles.ts COMPANY_EVENTS).
// instantiateStory() remaps a shared attack story onto THESE, so the EDR console
// shows the same host and IP the analyst just saw in the feed — correlation holds —
// instead of a generic NexaCorp workstation for every company. Kept here (the light
// module) so the adaptation layer needn't pull in the heavy event pools. Values are
// aligned with the real conventions in COMPANY_EVENTS; a regression gate asserts it.
export interface CompanyAssets {
  hosts:   string[]; // distinct endpoint names this company owns
  subnet:  string;   // dominant internal /24 (first three octets), e.g. "10.100.1"
  domain:  string;   // DNS / email domain, e.g. "quantumbank.ch"
  netbios: string;   // NetBIOS realm, e.g. "QUANTUMBANK"
}

export const COMPANY_ASSETS: Record<string, CompanyAssets> = {
  nexacorp: {
    hosts: ["WS-HR-1182", "WS-OPS-2214", "WS-MKT-3301", "WS-ACC-4477", "WS-ENG-2093",
            "WS-SALES-1876", "WS-FIN-1193", "WS-FIN-2847", "SRV-NXC-FS01", "SRV-NXC-DC01"],
    subnet: "10.10.20", domain: "nexacorp.com", netbios: "NEXACORP",
  },
  rocketstack: {
    hosts: ["LAP-007", "LAP-012", "LAP-003", "SRV-PROD-001", "macbook-ops-03",
            "LAP-DEV-12", "LAP-DEV-07", "WS-ENG-3301", "prod-srv-01"],
    subnet: "172.16.10", domain: "rocketstack.io", netbios: "ROCKETSTACK",
  },
  medcore: {
    hosts: ["WS-MED-022", "WS-MED-045", "WS-MED-067", "WS-NURS-033", "WS-NURS-044",
            "SRV-MEDCORE-EMR01", "SRV-MEDCORE-FILE01", "SRV-MEDCORE-DC01", "DC-MED-NL01", "NRS-TERM-088"],
    subnet: "192.168.10", domain: "medcorehealth.org", netbios: "MEDCORE",
  },
  globallogis: {
    hosts: ["SRV-GL-ERP01", "SRV-GL-WMS01", "WS-LOG-045", "WS-LOG-088", "WH-TERM-012",
            "WH-TERM-005", "DC-GL-FRA01", "SRV-GL-LINUX01", "SRV-GL-APP02", "SRV-GL-SAP01"],
    subnet: "10.50.10", domain: "globallogis.de", netbios: "GLOBALLOGIS",
  },
  quantumbank: {
    hosts: ["WKS-QB-012", "WKS-QB-020", "WKS-QB-033", "WKS-QB-055", "WKS-QB-077",
            "SRV-QB-ADMIN01", "SRV-QB-BACKUP01", "LAP-QB-4471", "LAP-QB-2290"],
    subnet: "10.100.1", domain: "quantumbank.ch", netbios: "QUANTUMBANK",
  },
};
