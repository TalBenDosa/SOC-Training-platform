/**
 * Synthetic enterprise identities, hostnames and network ranges.
 * Used by the log/alert generators to produce coherent investigations.
 */

export const COMPANY = {
  name: "Cryotech Industries",
  domain: "cryotech.io",
  ad_domain: "CRYOTECH",
  hq_country: "US",
  hq_city: "San Jose, CA",
};

export const SUBNETS = {
  corp:    "10.20.0.0/16",     // 10.20.x.x
  servers: "10.30.0.0/16",     // 10.30.x.x
  vpn:     "10.40.0.0/16",     // 10.40.x.x
  dmz:     "172.21.0.0/16",
  cloud:   "10.100.0.0/16",
} as const;

export const FIRST_NAMES = [
  "Avery","Riley","Jordan","Taylor","Casey","Morgan","Skyler","Drew","Quinn","Hayden",
  "Alex","Sam","Jamie","Cameron","Reese","Parker","Logan","Rowan","Emerson","Sage",
  "Priya","Arjun","Wei","Mei","Chen","Hiro","Yuki","Kenji","Aiko","Diego",
  "Sofia","Mateo","Lucia","Carlos","Elena","Olu","Adaeze","Fatima","Tariq","Noor",
];

export const LAST_NAMES = [
  "Park","Nguyen","Patel","Singh","Kim","Lopez","Garcia","Rivera","Chen","Wang",
  "Smith","Johnson","Brown","Davis","Miller","Wilson","Moore","Anderson","Thomas","Jackson",
  "Okafor","Mensah","Hassan","Khan","Ahmed","Cohen","Levi","Rossi","Müller","Schmidt",
];

export const DEPARTMENTS = [
  { code: "FIN",   name: "Finance",         risk: "high"   },
  { code: "HR",    name: "Human Resources", risk: "medium" },
  { code: "ENG",   name: "Engineering",     risk: "medium" },
  { code: "SEC",   name: "Security",        risk: "low"    },
  { code: "EXEC",  name: "Executive",       risk: "high"   },
  { code: "SALES", name: "Sales",           risk: "medium" },
  { code: "OPS",   name: "Operations",      risk: "low"    },
  { code: "LEGAL", name: "Legal",           risk: "high"   },
] as const;

export type Identity = {
  email: string;
  display_name: string;
  username: string;            // sAMAccountName
  upn: string;                 // user@domain
  department: string;
  title: string;
  hostname: string;            // primary endpoint
  os: "Windows 11" | "Windows 10" | "macOS 14" | "Ubuntu 22.04";
  ip: string;
  mfa: boolean;
  privileged: boolean;
};

export type Host = {
  name: string;
  os: Identity["os"];
  ip: string;
  role: "workstation" | "server" | "domain_controller" | "file_server" | "jump_host";
  owner_email?: string;
};

const TITLES_BY_DEPT: Record<string, string[]> = {
  FIN:   ["Financial Analyst", "Controller", "Treasury Manager", "AP Specialist"],
  HR:    ["HR Business Partner", "Recruiter", "People Ops Manager"],
  ENG:   ["Software Engineer", "Senior SWE", "Engineering Manager", "DevOps Engineer", "SRE"],
  SEC:   ["Security Engineer", "SOC Analyst", "Detection Engineer"],
  EXEC:  ["CFO", "CEO", "VP of Engineering", "Chief of Staff"],
  SALES: ["Account Executive", "Sales Engineer", "Customer Success Manager"],
  OPS:   ["IT Admin", "Helpdesk Lead", "Site Reliability"],
  LEGAL: ["General Counsel", "Paralegal", "Compliance Manager"],
};

export const SERVERS: Host[] = [
  { name: "DC01.cryotech.local",     os: "Windows 11", ip: "10.30.0.10", role: "domain_controller" },
  { name: "DC02.cryotech.local",     os: "Windows 11", ip: "10.30.0.11", role: "domain_controller" },
  { name: "FS-FIN01.cryotech.local", os: "Windows 11", ip: "10.30.4.21", role: "file_server" },
  { name: "FS-HR01.cryotech.local",  os: "Windows 11", ip: "10.30.4.22", role: "file_server" },
  { name: "JMP-ADMIN01",             os: "Windows 11", ip: "10.30.9.5",  role: "jump_host" },
  { name: "WEB-EDGE01",              os: "Ubuntu 22.04", ip: "172.21.1.10", role: "server" },
  { name: "APP-CRM01",               os: "Ubuntu 22.04", ip: "10.30.7.40", role: "server" },
];

import { rng, pick, hashString } from "./rng";

export function generateIdentities(count: number, seed = 42): Identity[] {
  const r = rng(seed);
  const out: Identity[] = [];
  const used = new Set<string>();
  while (out.length < count) {
    const fn = pick(r, FIRST_NAMES);
    const ln = pick(r, LAST_NAMES);
    const dept = pick(r, DEPARTMENTS);
    const username = `${fn[0].toLowerCase()}.${ln.toLowerCase()}`;
    if (used.has(username)) continue;
    used.add(username);
    const email = `${username}@${COMPANY.domain}`;
    const id = hashString(username);
    const ip = `10.20.${(id >> 8) & 0xff}.${(id & 0xff) || 23}`;
    out.push({
      email,
      display_name: `${fn} ${ln}`,
      username,
      upn: email,
      department: dept.code,
      title: pick(r, TITLES_BY_DEPT[dept.code] ?? ["Specialist"]),
      hostname: `WS-${dept.code}-${String((id % 9000) + 1000)}`,
      os: pick(r, ["Windows 11", "Windows 11", "Windows 10", "macOS 14"] as const),
      ip,
      mfa: r() > 0.15,
      privileged: dept.code === "SEC" || dept.code === "OPS" || (dept.code === "EXEC" && r() > 0.5),
    });
  }
  return out;
}
